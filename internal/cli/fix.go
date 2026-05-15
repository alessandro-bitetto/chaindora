package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/fixplan"
)

var (
	fixFromPath   string
	fixPlanID     string
	fixDryRun     bool
	fixYes        bool
	fixAggressive bool
)

var fixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Apply remediation from a findings JSON file or a saved fix-plan ID",
	Long: `Two input modes:

  --from <path>    Read findings from a previously-emitted JSON file
                   (the output of ` + "`chdora scan --format json`" + ` or any of
                   the other commands with --format=json). Builds a
                   fresh fix-plan, then runs the same pipeline that
                   --fix provides on the scan commands.

  --plan <id>      Apply a saved fix-plan by ID (produced by --save-plan
                   on scan/ci/forensics/audit). Bypasses scanning
                   entirely — you commit to what was generated.

Useful for CI workflows that scan once, archive the findings, review them,
then apply fixes in a separate step:

  chdora scan . --format json > findings.json
  chdora fix --from findings.json --yes              # apply safe fixes
  chdora fix --from findings.json --yes --aggressive # also semi-safe

Or for the audit-once-apply-later workflow:

  chdora audit --save-plan                  # writes plan, prints ID
  chdora fix --plan 2026-05-15-a3f2 --yes   # apply later, in a different shell
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if fixFromPath == "" && fixPlanID == "" {
			return fmt.Errorf("either --from <path> or --plan <id> is required")
		}
		if fixFromPath != "" && fixPlanID != "" {
			return fmt.Errorf("--from and --plan are mutually exclusive")
		}

		if fixPlanID != "" {
			return runFixFromPlanID(fixPlanID)
		}
		return runFixFromFindingsFile(fixFromPath)
	},
}

func runFixFromFindingsFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var fs []findings.Finding
	if err := json.Unmarshal(data, &fs); err != nil {
		return fmt.Errorf("parse %s as a findings JSON array: %w", path, err)
	}
	if len(fs) == 0 {
		fmt.Fprintln(os.Stderr, "no findings in input file")
		return nil
	}
	fmt.Fprintf(os.Stderr, "loaded %d finding(s) from %s\n", len(fs), path)

	plans := buildAllFixPlans(fs)
	allowed := []findings.FixCategory{findings.FixSafe}
	if fixAggressive {
		allowed = append(allowed, findings.FixSemiSafe)
	}
	_, _, err = findings.RunFixes(context.Background(), plans, findings.RunOptions{
		PlanOnly:          fixDryRun,
		AutoYes:           fixYes,
		AllowedCategories: allowed,
	})
	return err
}

func runFixFromPlanID(id string) error {
	store, err := fixplan.Default()
	if err != nil {
		return err
	}
	plan, err := store.Load(id)
	if err != nil {
		return formatPlanError(err, id)
	}
	return applyStoredPlan(context.Background(), store, plan, applyOpts{
		Aggressive: fixAggressive,
		AutoYes:    fixYes,
		DryRun:     fixDryRun,
	})
}

func init() {
	fixCmd.Flags().StringVar(&fixFromPath, "from", "", "path to a findings JSON file (produced by --format json on scan/ci/forensics)")
	fixCmd.Flags().StringVar(&fixPlanID, "plan", "", "ID of a saved fix-plan to apply (see `chdora plans list`)")
	fixCmd.Flags().BoolVar(&fixDryRun, "dry-run", false, "describe the remediation plan for each finding without executing anything")
	fixCmd.Flags().BoolVar(&fixYes, "yes", false, "auto-apply all `safe` fixes without prompting")
	fixCmd.Flags().BoolVar(&fixAggressive, "aggressive", false, "also auto-apply `semi-safe` fixes under --yes (project-lockfile upgrades, uninstalls)")
	rootCmd.AddCommand(fixCmd)
}
