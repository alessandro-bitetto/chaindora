package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/alessandro-bitetto/chaindora/internal/detectors/heuristic"
	"github.com/alessandro-bitetto/chaindora/internal/detectors/incident"
	"github.com/alessandro-bitetto/chaindora/internal/detectors/osvioc"
	"github.com/alessandro-bitetto/chaindora/internal/detectors/predictive"
	"github.com/alessandro-bitetto/chaindora/internal/gate"
	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/incidents"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
	"github.com/alessandro-bitetto/chaindora/internal/osv"
)

var (
	ciFailOn         string
	ciFormat         string
	ciSARIFPath      string
	ciIncidentsDir   string
	ciSkipOSV        bool
	ciSkipPredictive bool
	ciSkipIncidents  bool
	ciSkipHeuristic  bool
	ciFreshPopular   bool
	ciVerbose        bool
	ciExcludes       []string
	ciFixPlan        bool
	ciFix            bool
	ciYes            bool
	ciAggressive     bool
	ciSavePlan       bool
	ciSkipRegistry   bool
	ciExcludeCVEs       bool
	ciExcludeSupply     bool
	ciExcludeConfig     bool
	ciExcludeHost       bool
	ciExcludePredictive bool
	ciOffline        bool
	// SonarQube-grade CI surface (v0.10).
	ciBaselinePath       string
	ciUpdateBaseline     bool
	ciSuppressFile       string
	ciIgnoreSuppressions bool
	ciCommentPath        string
)

var ciCmd = &cobra.Command{
	Use:   "ci [path]",
	Short: "Run chdora as a CI gate (autodetects environment, exits non-zero on findings)",
	Long: `chdora ci is a thin wrapper over scan with semantics tuned for
continuous-integration use:

  - Autodetects the running CI (GitHub Actions, GitLab CI, CircleCI, Bitbucket
    Pipelines, Azure Pipelines, Drone, Jenkins) and picks an appropriate
    primary output format.
  - Exits with code 1 if any finding meets the --fail-on threshold
    (default: critical,high). Use 'any' to fail on any finding, 'none' to
    always exit 0.
  - --sarif <path> writes a SARIF 2.1.0 sidecar file alongside the chosen
    primary format, ready for upload to GitHub code-scanning, GitLab security
    dashboards, etc.
  - Quieter than scan by default — use --verbose to restore diagnostic output.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		root := "."
		if len(args) == 1 {
			root = args[0]
		}

		if ciOffline {
			ciSkipOSV = true
			ciSkipRegistry = true
		}

		ci := detectCI(os.Getenv)
		format := ciFormat
		if format == "" {
			format = formatForCI(ci)
		}
		if ciVerbose {
			fmt.Fprintf(os.Stderr, "chdora ci: detected env=%q, format=%q\n", ci, format)
		}

		inv, err := inventory.Scan(root, inventory.WithExcludes(ciExcludes...))
		if err != nil {
			return fmt.Errorf("inventory: %w", err)
		}
		if ciVerbose {
			fmt.Fprintf(os.Stderr, "inventoried %d packages from %d sources\n",
				len(inv.Packages), len(inv.Sources))
			for _, e := range inv.Errors {
				fmt.Fprintln(os.Stderr, "warn:", e)
			}
		}

		ctx := context.Background()
		var all []findings.Finding
		tally := newDetectorTally()

		if !ciSkipOSV {
			tally.Enable("osv-ioc")
			det := osvioc.New(osv.NewClient())
			results, err := det.Detect(ctx, inv)
			if err != nil {
				return fmt.Errorf("osv detector: %w", err)
			}
			tally.AbsorbFindings(results)
			all = append(all, results...)
		}

		if !ciSkipIncidents {
			dir := incidents.ResolveDir([]string{
				ciIncidentsDir,
				"incidents",
				filepath.Join(os.Getenv("HOME"), ".chaindora", "incidents"),
			})
			if dir != "" {
				incs, err := incidents.LoadDir(dir)
				if err != nil {
					if ciVerbose {
						fmt.Fprintln(os.Stderr, "warn: incident pack load failed:", err)
					}
				} else {
					tally.Enable("incident-pack")
					det := incident.New(incs, ciExcludes...)
					results, err := det.Detect(ctx, inv, root)
					if err != nil {
						return fmt.Errorf("incident detector: %w", err)
					}
					tally.AbsorbFindings(results)
					all = append(all, results...)
				}
			}
		}

		if !ciSkipHeuristic {
			tally.Enable("heuristic")
			npm, pypi := buildRegistryProbes(ciSkipRegistry)
			det := heuristic.New(heuristic.Config{
				FreshPopular: heuristic.FreshPopularConfig{Enabled: ciFreshPopular},
				Excludes:     ciExcludes,
				NPMProbe:     npm,
				PyPIProbe:    pypi,
			})
			results, err := det.Detect(ctx, inv, root)
			if err != nil {
				return fmt.Errorf("heuristic detector: %w", err)
			}
			tally.AbsorbFindings(results)
			all = append(all, results...)
		}

		// Predictive layer: gate-style behavioral signals replayed
		// against installed packages. Defaults to severity=medium so
		// the default --fail-on=critical,high CI gate stays quiet;
		// republish-guard (cache-based) escalates to critical.
		if !ciSkipPredictive && !ciSkipRegistry {
			tally.Enable("predictive")
			probes := buildGateProbes()
			cache := gate.NewCache(gate.DefaultCacheRoot(), 7*24*time.Hour)
			det := predictive.New(probes, 72*time.Hour, cache)
			results, err := det.Detect(ctx, inv)
			if err != nil {
				if ciVerbose {
					fmt.Fprintln(os.Stderr, "warn: predictive detector:", err)
				}
			} else {
				tally.AbsorbFindings(results)
				all = append(all, results...)
			}
		}

		tally.Print(os.Stderr)

		// SonarQube-grade CI pipeline:
		//   1. Load suppression file → split (kept, suppressed)
		//   2. Load baseline → diff against current → (new, removed)
		//   3. Render based on the chosen format
		//   4. Apply fail-on against ONLY the new findings (not pre-existing)
		//   5. Optionally update baseline / emit PR-comment markdown
		//
		// Steps 1+2+4 reframe the "ci as a PR gate" model:
		//   - pre-existing tech-debt findings DON'T break new PRs
		//   - explicitly-suppressed findings (with reason) DON'T break new PRs
		//   - only ACTUAL NEW findings on this PR can fail the gate
		suppressions, suppErr := findings.LoadSuppressions(ciSuppressFileOrDefault(root))
		if suppErr != nil && !ciIgnoreSuppressions {
			return fmt.Errorf("suppression file: %w", suppErr)
		}
		var suppressed []findings.SuppressedFinding
		if !ciIgnoreSuppressions {
			all, suppressed = findings.FilterSuppressed(all, suppressions, time.Now())
		}
		// Emit expired-suppression warning to stderr regardless of
		// format — this is operational signal, not finding data.
		expiredCount := 0
		for _, s := range suppressed {
			if s.Expired {
				expiredCount++
			}
		}
		if expiredCount > 0 {
			fmt.Fprintf(os.Stderr, "[chdora] WARNING: %d expired suppression entry(ies) in %s — review and refresh\n",
				expiredCount, suppressions.Path)
		}

		var newFindings []findings.Finding
		var removedFps []string
		if ciBaselinePath != "" {
			baseline, err := findings.LoadBaseline(ciBaselinePath)
			if err != nil {
				return fmt.Errorf("baseline: %w", err)
			}
			newFindings, removedFps = findings.DiffAgainstBaseline(all, baseline)
			if baseline == nil {
				fmt.Fprintf(os.Stderr, "[chdora] no existing baseline at %s — every current finding is treated as NEW.\n", ciBaselinePath)
				fmt.Fprintln(os.Stderr, "[chdora]   Run `chdora ci --baseline <path> --update-baseline` after fixing or accepting the current state to lock it in.")
			} else if ciVerbose {
				fmt.Fprintf(os.Stderr, "[chdora] baseline diff: %d new, %d resolved\n", len(newFindings), len(removedFps))
			}
		} else {
			newFindings = all
		}

		ExcludeCVEs = ciExcludeCVEs
		ExcludeSupplyChain = ciExcludeSupply
		ExcludeConfig = ciExcludeConfig
		ExcludeHost = ciExcludeHost
		ExcludePredictive = ciExcludePredictive
		// pr-comment is a new format that bypasses the standard
		// renderer. Everything else still flows through renderFindings.
		if format == "pr-comment" {
			if err := findings.EmitPRComment(os.Stdout, all, suppressed, newFindings, removedFps, Version); err != nil {
				return err
			}
		} else {
			if err := renderFindings(os.Stdout, all, format); err != nil {
				return err
			}
		}
		// Optional separate file for the PR comment — useful when
		// the primary format is text/sarif but the CI workflow still
		// wants a markdown comment to post.
		if ciCommentPath != "" {
			f, err := os.Create(ciCommentPath)
			if err != nil {
				return fmt.Errorf("pr-comment sidecar: %w", err)
			}
			if err := findings.EmitPRComment(f, all, suppressed, newFindings, removedFps, Version); err != nil {
				f.Close()
				return fmt.Errorf("pr-comment emit: %w", err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("pr-comment close: %w", err)
			}
			if ciVerbose {
				fmt.Fprintf(os.Stderr, "[chdora] wrote PR comment to %s\n", ciCommentPath)
			}
		}

		if ciSARIFPath != "" {
			f, err := os.Create(ciSARIFPath)
			if err != nil {
				return fmt.Errorf("sarif sidecar: %w", err)
			}
			if err := findings.EmitSARIF(f, all, Version); err != nil {
				f.Close()
				return fmt.Errorf("sarif emit: %w", err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("sarif close: %w", err)
			}
			if ciVerbose {
				fmt.Fprintf(os.Stderr, "wrote SARIF to %s\n", ciSARIFPath)
			}
		}

		plans := buildAllFixPlans(all)
		var savedID string
		if ciSavePlan && len(plans) > 0 {
			id, sErr := saveFixPlan(plans, len(all), root)
			if sErr != nil {
				return fmt.Errorf("save plan: %w", sErr)
			}
			savedID = id
		}
		if ciFixPlan || ciFix {
			allowed := []findings.FixCategory{findings.FixSafe}
			if ciAggressive {
				allowed = append(allowed, findings.FixSemiSafe)
			}
			_, _, fErr := findings.RunFixes(ctx, plans, findings.RunOptions{
				PlanOnly:          ciFixPlan && !ciFix,
				AutoYes:           ciYes,
				AllowedCategories: allowed,
			})
			if fErr != nil {
				return fErr
			}
		}
		saved := ciSavePlan && savedID != ""
		fixRequested := ciFixPlan || ciFix
		// `chdora ci` is non-interactive by intent — the prompt
		// helper used by `scan` / `forensics` is intentionally
		// omitted here. The end-of-run footer still tells the user
		// how to save a plan if they want one.
		emitEndOfRunFooter(os.Stderr, plans, saved, savedID, fixRequested)

		// Update baseline AFTER all rendering so the file's
		// final state reflects what was actually scanned this run.
		if ciUpdateBaseline && ciBaselinePath != "" {
			newBaseline := findings.BaselineFromFindings(all, Version, time.Now().UTC().Format(time.RFC3339))
			if err := findings.SaveBaseline(ciBaselinePath, newBaseline); err != nil {
				return fmt.Errorf("update baseline: %w", err)
			}
			fmt.Fprintf(os.Stderr, "[chdora] baseline updated at %s (%d fingerprint(s) recorded)\n",
				ciBaselinePath, len(newBaseline.Fingerprints))
		}

		// SonarQube-style gate: --fail-on applies to the NEW set
		// (post-suppression, post-baseline-diff) — not the
		// full inventory. Pre-existing tech debt doesn't fail
		// the PR; only what this PR introduced does.
		if shouldFail(newFindings, ciFailOn) {
			os.Exit(1)
		}
		return nil
	},
}

// ciSuppressFileOrDefault picks the suppression-file location.
// Explicit --suppress-file wins; otherwise the standard
// .chaindora-ignore.yml discovery walks up from the scan root.
func ciSuppressFileOrDefault(root string) string {
	if ciSuppressFile != "" {
		return ciSuppressFile
	}
	return root
}

// detectCI returns a short identifier for the running CI, or "" if none of
// the well-known indicator variables are set. getenv is parameterized for
// testability.
func detectCI(getenv func(string) string) string {
	switch {
	case getenv("GITHUB_ACTIONS") == "true":
		return "github-actions"
	case getenv("GITLAB_CI") == "true":
		return "gitlab-ci"
	case getenv("CIRCLECI") == "true":
		return "circleci"
	case getenv("BITBUCKET_BUILD_NUMBER") != "":
		return "bitbucket"
	case getenv("TF_BUILD") == "True":
		return "azure-pipelines"
	case getenv("DRONE") == "true":
		return "drone"
	case getenv("JENKINS_HOME") != "" || getenv("BUILD_TAG") != "":
		return "jenkins"
	}
	return ""
}

// formatForCI maps a detected CI environment to its recommended primary
// output format. GitHub Actions gets inline annotations (::error file=...);
// everything else gets human-readable text on the assumption that logs are
// read by humans and structured output goes via the --sarif sidecar.
func formatForCI(ci string) string {
	if ci == "github-actions" {
		return "github"
	}
	return "text"
}

// shouldFail returns true if any finding meets the failure threshold.
// threshold is a comma-separated severity list, "any", or "none".
func shouldFail(fs []findings.Finding, threshold string) bool {
	t := strings.ToLower(strings.TrimSpace(threshold))
	switch t {
	case "", "none":
		return false
	case "any":
		return len(fs) > 0
	}
	wanted := map[string]bool{}
	for _, level := range strings.Split(t, ",") {
		wanted[strings.ToUpper(strings.TrimSpace(level))] = true
	}
	for _, f := range fs {
		if wanted[string(f.Severity)] {
			return true
		}
	}
	return false
}

func init() {
	ciCmd.Flags().StringVar(&ciFailOn, "fail-on", "critical,high",
		"comma-separated severities causing exit 1, or 'any' / 'none'")
	ciCmd.Flags().StringVar(&ciFormat, "format", "",
		"output format: text|json|jsonl|sarif|github (default: autodetect from CI)")
	ciCmd.Flags().StringVar(&ciSARIFPath, "sarif", "",
		"also write SARIF 2.1.0 to this path (for upload to code-scanning dashboards)")
	ciCmd.Flags().StringVar(&ciIncidentsDir, "incidents", "",
		"path to incident-pack YAML directory")
	ciCmd.Flags().BoolVar(&ciSkipOSV, "skip-osv", false, "skip OSV.dev queries")
	ciCmd.Flags().BoolVar(&ciSkipIncidents, "skip-incidents", false, "skip the curated incident pack")
	ciCmd.Flags().BoolVar(&ciSkipHeuristic, "skip-heuristic", false, "skip behavioral heuristics")
	ciCmd.Flags().BoolVar(&ciSkipPredictive, "skip-predictive", false, "skip the predictive detector (gate-style behavioral signals replayed against installed packages)")
	ciCmd.Flags().BoolVar(&ciFreshPopular, "fresh-popular", false, "also check publish dates of top-N popular npm/PyPI deps (requires network)")
	ciCmd.Flags().BoolVar(&ciSkipRegistry, "skip-registry", false, "do not query npm/PyPI for evidence (offline mode; evidence-based heuristics become silent)")
	ciCmd.Flags().BoolVar(&ciExcludeCVEs, "exclude-cves", false, "hide the dependency-CVE section")
	ciCmd.Flags().BoolVar(&ciExcludeSupply, "exclude-supply-chain", false, "hide the supply-chain attack section")
	ciCmd.Flags().BoolVar(&ciExcludeConfig, "exclude-config", false, "hide the configuration-risks section")
	ciCmd.Flags().BoolVar(&ciExcludeHost, "exclude-host", false, "hide the host-state section")
	ciCmd.Flags().BoolVar(&ciExcludePredictive, "exclude-predictive", false, "hide the predictive-signals section (gate-style behavioral checks on installed packages)")
	ciCmd.Flags().BoolVar(&ciOffline, "offline", false, "no network calls — implies --skip-osv and --skip-registry")
	ciCmd.Flags().BoolVar(&ciVerbose, "verbose", false, "emit diagnostic logs to stderr")
	ciCmd.Flags().StringSliceVar(&ciExcludes, "exclude", nil, "directory basename(s) to skip (repeatable or comma-separated)")
	ciCmd.Flags().BoolVar(&ciFixPlan, "fix-plan", false, "describe a remediation plan for each finding without executing anything")
	ciCmd.Flags().BoolVar(&ciFix, "fix", false, "after scanning, prompt to apply remediation for each finding (use --yes to auto-apply safe fixes)")
	ciCmd.Flags().BoolVar(&ciYes, "yes", false, "auto-apply all fixes classified `safe` without prompting (requires --fix)")
	ciCmd.Flags().BoolVar(&ciAggressive, "fix-aggressive", false, "also auto-apply `semi-safe` fixes under --yes")
	ciCmd.Flags().BoolVar(&ciSavePlan, "save-plan", false, "save the generated fix-plan to ~/.chaindora/fix-plans/ and print its ID")
	// v0.10 SonarQube-grade CI surface.
	ciCmd.Flags().StringVar(&ciBaselinePath, "baseline", "", "path to a baseline findings file. --fail-on is then applied only to findings NEW since the baseline (not pre-existing tech debt). Combine with --update-baseline.")
	ciCmd.Flags().BoolVar(&ciUpdateBaseline, "update-baseline", false, "after the scan, rewrite the baseline file to reflect the current findings. Use after intentional resolution / acceptance.")
	ciCmd.Flags().StringVar(&ciSuppressFile, "suppress-file", "", "path to a .chaindora-ignore.yml. Default: walks up from the scan root looking for .chaindora-ignore.yml")
	ciCmd.Flags().BoolVar(&ciIgnoreSuppressions, "ignore-suppressions", false, "process all findings even if the suppression file matches some — use for full audits")
	ciCmd.Flags().StringVar(&ciCommentPath, "pr-comment", "", "additionally write a GitHub-flavored markdown PR-comment body to this file (sticky-comment compatible)")
	rootCmd.AddCommand(ciCmd)
}
