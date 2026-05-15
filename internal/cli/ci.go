package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/alessandro-bitetto/chaindora/internal/detectors/heuristic"
	"github.com/alessandro-bitetto/chaindora/internal/detectors/incident"
	"github.com/alessandro-bitetto/chaindora/internal/detectors/osvioc"
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
	ciSkipIncidents  bool
	ciSkipHeuristic  bool
	ciFreshPopular   bool
	ciVerbose        bool
	ciExcludes       []string
	ciFixPlan        bool
	ciFix            bool
	ciYes            bool
	ciAggressive     bool
)

var ciCmd = &cobra.Command{
	Use:   "ci [path]",
	Short: "Run chaindora as a CI gate (autodetects environment, exits non-zero on findings)",
	Long: `chaindora ci is a thin wrapper over scan with semantics tuned for
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

		ci := detectCI(os.Getenv)
		format := ciFormat
		if format == "" {
			format = formatForCI(ci)
		}
		if ciVerbose {
			fmt.Fprintf(os.Stderr, "chaindora ci: detected env=%q, format=%q\n", ci, format)
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

		if !ciSkipOSV {
			det := osvioc.New(osv.NewClient())
			results, err := det.Detect(ctx, inv)
			if err != nil {
				return fmt.Errorf("osv detector: %w", err)
			}
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
					det := incident.New(incs, ciExcludes...)
					results, err := det.Detect(ctx, inv, root)
					if err != nil {
						return fmt.Errorf("incident detector: %w", err)
					}
					all = append(all, results...)
				}
			}
		}

		if !ciSkipHeuristic {
			det := heuristic.New(heuristic.Config{
				FreshPopular: heuristic.FreshPopularConfig{Enabled: ciFreshPopular},
				Excludes:     ciExcludes,
			})
			results, err := det.Detect(ctx, inv, root)
			if err != nil {
				return fmt.Errorf("heuristic detector: %w", err)
			}
			all = append(all, results...)
		}

		if err := renderFindings(os.Stdout, all, format); err != nil {
			return err
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

		if ciFixPlan || ciFix {
			plans := buildAllFixPlans(all)
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

		if shouldFail(all, ciFailOn) {
			os.Exit(1)
		}
		return nil
	},
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
	ciCmd.Flags().BoolVar(&ciFreshPopular, "fresh-popular", false, "also check publish dates of top-N popular npm/PyPI deps (requires network)")
	ciCmd.Flags().BoolVar(&ciVerbose, "verbose", false, "emit diagnostic logs to stderr")
	ciCmd.Flags().StringSliceVar(&ciExcludes, "exclude", nil, "directory basename(s) to skip (repeatable or comma-separated)")
	ciCmd.Flags().BoolVar(&ciFixPlan, "fix-plan", false, "describe a remediation plan for each finding without executing anything")
	ciCmd.Flags().BoolVar(&ciFix, "fix", false, "after scanning, prompt to apply remediation for each finding (use --yes to auto-apply safe fixes)")
	ciCmd.Flags().BoolVar(&ciYes, "yes", false, "auto-apply all fixes classified `safe` without prompting (requires --fix)")
	ciCmd.Flags().BoolVar(&ciAggressive, "fix-aggressive", false, "also auto-apply `semi-safe` fixes under --yes")
	rootCmd.AddCommand(ciCmd)
}
