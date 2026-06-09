package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/fixplan"
)

// `chdora plans …` manages fix plans saved by `--save-plan`. The
// subcommand tree (list / show / delete / prune / apply) is
// deliberately kept narrow — anything more complex (diffs, merges,
// re-runs) is a future concern.
var plansCmd = &cobra.Command{
	Use:   "plans",
	Short: "Manage saved fix plans (~/.chaindora/fix-plans/)",
	Long: `Fix plans are JSON snapshots of "everything chdora would fix right now,"
produced by ` + "`--save-plan`" + ` on scan / ci / forensics / audit. The plans
subcommand tree lets you list, inspect, apply, and clean them up far
from where they were generated.

Typical workflow:

  chdora audit --save-plan          # writes plan, prints its ID
  chdora plans list                  # see what's saved
  chdora plans show <id>             # full plan output
  chdora fix --plan <id> --yes       # apply later, in a different shell
  chdora plans prune --older-than 30d
`,
}

var plansListCmd = &cobra.Command{
	Use:   "list",
	Short: "List saved fix plans (most recent first)",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := fixplan.Default()
		if err != nil {
			return err
		}
		summaries, err := store.List()
		if err != nil {
			return err
		}
		if len(summaries) == 0 {
			fmt.Fprintln(os.Stderr, "no saved plans (use --save-plan on scan / ci / forensics / audit to create one)")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tCREATED\tFIXES\tSAFE\tSEMI\tMANUAL\tSTATUS\tCOMMAND")
		for _, s := range summaries {
			fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\n",
				s.ID,
				s.CreatedAt.Local().Format("2006-01-02 15:04"),
				s.PlanCount,
				s.Categories.Safe,
				s.Categories.SemiSafe,
				s.Categories.Manual,
				s.Status(),
				truncate(s.ScanCommand, 50),
			)
		}
		return w.Flush()
	},
}

var plansShowCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "Display a saved fix plan (header + per-fix detail)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := fixplan.Default()
		if err != nil {
			return err
		}
		plan, err := store.Load(args[0])
		if err != nil {
			return formatPlanError(err, args[0])
		}
		renderPlanShow(os.Stdout, plan)
		return nil
	},
}

var plansDeleteCmd = &cobra.Command{
	Use:     "delete <id>",
	Aliases: []string{"rm"},
	Short:   "Delete a saved fix plan",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := fixplan.Default()
		if err != nil {
			return err
		}
		if err := store.Delete(args[0]); err != nil {
			return formatPlanError(err, args[0])
		}
		fmt.Fprintf(os.Stderr, "deleted plan %s\n", args[0])
		return nil
	},
}

var plansPruneOlderThan string

var plansPruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Delete saved plans older than a given duration",
	Long: `Removes plans whose creation timestamp is older than --older-than ago.
Duration accepts Go duration syntax (e.g. 720h) or a shorthand suffix
(e.g. 30d, 12w). Default 30d.

  chdora plans prune                 # default: 30d
  chdora plans prune --older-than 7d
  chdora plans prune --older-than 168h
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dur, err := parseDuration(plansPruneOlderThan)
		if err != nil {
			return fmt.Errorf("--older-than: %w", err)
		}
		store, err := fixplan.Default()
		if err != nil {
			return err
		}
		deleted, err := store.Prune(dur)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "pruned %d plan(s) older than %s\n", deleted, dur)
		return nil
	},
}

var plansApplyAggressive bool
var plansApplyYes bool
var plansApplyDryRun bool

var plansApplyCmd = &cobra.Command{
	Use:   "apply <id>",
	Short: "Apply a saved fix plan (shortcut for `chdora fix --plan <id>`)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := fixplan.Default()
		if err != nil {
			return err
		}
		plan, err := store.Load(args[0])
		if err != nil {
			return formatPlanError(err, args[0])
		}
		return applyStoredPlan(context.Background(), store, plan, applyOpts{
			Aggressive: plansApplyAggressive,
			AutoYes:    plansApplyYes,
			DryRun:     plansApplyDryRun,
		})
	},
}

// applyOpts is shared between `chdora plans apply` and the `--plan`
// branch of `chdora fix`. Keeps the two surfaces from diverging.
type applyOpts struct {
	Aggressive bool
	AutoYes    bool
	DryRun     bool
}

// emitPriorApplyBanner surfaces the "this plan was already applied"
// signal that v0.8.2 was missing. When a user re-runs `chdora fix
// --plan <id>` against an already-applied plan, the preflight check
// silently drops every fix as already-satisfied and the runner says
// "no fixable findings" — accurate but mysterious. The banner tells
// the user what's happening up front so they don't burn a fifth run
// trying to "make it work."
//
// We never refuse the re-apply: the lockfile is the source of truth,
// preflight is the authoritative check, and there are real cases
// where re-applying is desired (a teammate rolled back the install,
// the project was reset from git, etc.). Just inform.
func emitPriorApplyBanner(w io.Writer, plan fixplan.Plan) {
	if plan.AppliedAt == nil {
		return
	}
	applied, satisfied, skipped := 0, 0, 0
	for _, r := range plan.AppliedResults {
		switch r.Status {
		case "applied":
			applied++
		case "already-satisfied":
			satisfied++
		case "skipped":
			skipped++
		}
	}
	fmt.Fprintf(w, "[chdora] NOTE: this plan was previously applied %s — applied=%d already-satisfied=%d skipped=%d\n",
		plan.AppliedAt.Local().Format("2006-01-02 15:04:05"), applied, satisfied, skipped)
	fmt.Fprintln(w, "        re-applying anyway — preflight will skip anything already at the required version.")
}

// applyStoredPlan runs the fixes recorded in a saved plan and writes
// back the results so `plans list` shows the applied status. It does
// not re-run the scan — that is the whole point of saved plans: you
// commit to what was generated and just execute it.
func applyStoredPlan(ctx context.Context, store *fixplan.DiskStore, plan fixplan.Plan, opts applyOpts) error {
	if len(plan.Plans) == 0 {
		fmt.Fprintf(os.Stderr, "plan %s has no fixes\n", plan.ID)
		return nil
	}
	allowed := []findings.FixCategory{findings.FixSafe}
	if opts.Aggressive {
		allowed = append(allowed, findings.FixSemiSafe)
	}
	fmt.Fprintf(os.Stderr, "applying plan %s (%d fix(es), created %s)\n",
		plan.ID, len(plan.Plans), plan.CreatedAt.Local().Format("2006-01-02 15:04"))
	emitPriorApplyBanner(os.Stderr, plan)
	filtered, skipped, notes := preflightFilterSatisfied(plan.Plans)
	emitPreflightNotes(os.Stderr, notes, skipped)
	runnable, unwritable, uwNotes := preflightFilterUnwritable(filtered)
	emitUnwritableNotes(os.Stderr, uwNotes)
	_, _, err := findings.RunFixes(ctx, runnable, findings.RunOptions{
		PlanOnly:          opts.DryRun,
		AutoYes:           opts.AutoYes,
		AllowedCategories: allowed,
	})
	if err != nil {
		return err
	}
	if opts.DryRun {
		return nil
	}
	// Identify which plans were dropped by preflight so we record
	// them as "already-satisfied" instead of the generic "skipped".
	satisfiedFP := map[string]bool{}
	for _, fp := range plan.Plans {
		dropped := true
		for _, kept := range filtered {
			if kept.FindingFingerprint == fp.FindingFingerprint {
				dropped = false
				break
			}
		}
		if dropped {
			satisfiedFP[fp.FindingFingerprint] = true
		}
	}
	results := make([]fixplan.AppliedResult, 0, len(plan.Plans))
	now := time.Now().UTC()
	for i, fp := range plan.Plans {
		status := "skipped"
		switch {
		case satisfiedFP[fp.FindingFingerprint]:
			status = "already-satisfied"
		case unwritable[fp.FindingFingerprint]:
			// Dropped by the writability/vendored preflight — it was
			// never run, so it's "skipped", not "applied".
			status = "skipped"
		case contains(allowed, fp.Category):
			status = "applied"
		}
		results = append(results, fixplan.AppliedResult{
			FixIndex:  i,
			VulnID:    fp.VulnID,
			Status:    status,
			AppliedAt: now,
		})
	}
	if err := store.MarkApplied(plan.ID, results); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to record apply-history on plan %s: %v\n", plan.ID, err)
	}
	return nil
}

func contains(cs []findings.FixCategory, c findings.FixCategory) bool {
	for _, x := range cs {
		if x == c {
			return true
		}
	}
	return false
}

func renderPlanShow(w *os.File, plan fixplan.Plan) {
	fmt.Fprintf(w, "Plan: %s\n", plan.ID)
	fmt.Fprintf(w, "Created: %s\n", plan.CreatedAt.Local().Format(time.RFC3339))
	if plan.ChdoraVersion != "" {
		fmt.Fprintf(w, "chdora version: %s\n", plan.ChdoraVersion)
	}
	if plan.ScanCommand != "" {
		fmt.Fprintf(w, "Command: %s\n", plan.ScanCommand)
	}
	if plan.ScanRoot != "" {
		fmt.Fprintf(w, "Scan root: %s\n", plan.ScanRoot)
	}
	fmt.Fprintf(w, "Total findings at scan time: %d\n", plan.TotalFindings)
	cats := plan.Categories()
	fmt.Fprintf(w, "Fixes: %d total (safe=%d semi-safe=%d unsafe=%d manual=%d)\n",
		len(plan.Plans), cats.Safe, cats.SemiSafe, cats.Unsafe, cats.Manual)
	if plan.AppliedAt != nil {
		applied := 0
		for _, r := range plan.AppliedResults {
			if r.Status == "applied" {
				applied++
			}
		}
		fmt.Fprintf(w, "Applied: %s (%d/%d)\n",
			plan.AppliedAt.Local().Format(time.RFC3339), applied, len(plan.Plans))
	} else {
		fmt.Fprintln(w, "Applied: never")
	}
	fmt.Fprintln(w)

	// Stable per-category grouping so re-runs of `plans show` produce
	// the same output even if Plans slice ordering shifts.
	groups := map[findings.FixCategory][]findings.FixPlan{}
	for _, fp := range plan.Plans {
		groups[fp.Category] = append(groups[fp.Category], fp)
	}
	order := []findings.FixCategory{findings.FixSafe, findings.FixSemiSafe, findings.FixUnsafe, findings.FixManual}
	for _, cat := range order {
		fps := groups[cat]
		if len(fps) == 0 {
			continue
		}
		sort.Slice(fps, func(i, j int) bool { return fps[i].VulnID < fps[j].VulnID })
		fmt.Fprintf(w, "── %s (%d) ──\n", cat, len(fps))
		for _, fp := range fps {
			fmt.Fprintf(w, "  [%s] %s\n", fp.Severity, fp.Description)
			if fp.Command != "" {
				fmt.Fprintf(w, "    $ %s\n", fp.Command)
			}
			for _, step := range fp.ManualSteps {
				fmt.Fprintf(w, "    • %s\n", step)
			}
		}
		fmt.Fprintln(w)
	}
}

// formatPlanError turns the package's typed errors into user-friendly
// CLI messages. We want "plan foo not found" not "plan not found"
// since the user might have several stale IDs in their head.
func formatPlanError(err error, id string) error {
	if errors.Is(err, fixplan.ErrNotFound) {
		return fmt.Errorf("no plan with id %q (run `chdora plans list` to see saved plans)", id)
	}
	return err
}

// parseDuration accepts Go's standard durations plus the shorthand
// suffixes `d` (days) and `w` (weeks), which Go itself refuses but
// users overwhelmingly expect for "older than 30 days" style flags.
func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 30 * 24 * time.Hour, nil
	}
	switch {
	case strings.HasSuffix(s, "d"):
		n, err := parseUint(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	case strings.HasSuffix(s, "w"):
		n, err := parseUint(strings.TrimSuffix(s, "w"))
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 7 * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func parseUint(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty number")
	}
	var n int
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a number: %q", s)
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 1 {
		return ""
	}
	return s[:n-1] + "…"
}

func init() {
	plansPruneCmd.Flags().StringVar(&plansPruneOlderThan, "older-than", "30d", "delete plans older than this (e.g. 30d, 12w, 720h)")

	plansApplyCmd.Flags().BoolVar(&plansApplyAggressive, "aggressive", false, "also auto-apply `semi-safe` fixes under --yes (project-lockfile upgrades, uninstalls)")
	plansApplyCmd.Flags().BoolVar(&plansApplyYes, "yes", false, "auto-apply all `safe` fixes without prompting")
	plansApplyCmd.Flags().BoolVar(&plansApplyDryRun, "dry-run", false, "describe the remediation plan without executing anything")

	plansCmd.AddCommand(plansListCmd, plansShowCmd, plansDeleteCmd, plansPruneCmd, plansApplyCmd)
	rootCmd.AddCommand(plansCmd)
}
