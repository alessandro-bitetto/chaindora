package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

var (
	fixFromPath   string
	fixPlanOnly   bool
	fixYes        bool
	fixAggressive bool
)

var fixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Apply remediation against findings from a saved JSON file",
	Long: `Read findings from a JSON file (the output of ` + "`chdora scan --format json`" + `
or any of the other commands with --format=json) and run the same fix
pipeline that --fix provides on the scan commands — without re-scanning.

Useful for CI workflows that scan once, archive the findings, review them,
then apply fixes in a separate step:

  chdora scan . --format json > findings.json
  # review findings.json, ship to security review, etc.
  chdora fix --from findings.json --yes              # apply safe fixes
  chdora fix --from findings.json --yes --aggressive # also semi-safe`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if fixFromPath == "" {
			return fmt.Errorf("--from <path> is required")
		}
		data, err := os.ReadFile(fixFromPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", fixFromPath, err)
		}
		var fs []findings.Finding
		if err := json.Unmarshal(data, &fs); err != nil {
			return fmt.Errorf("parse %s as a findings JSON array: %w", fixFromPath, err)
		}
		if len(fs) == 0 {
			fmt.Fprintln(os.Stderr, "no findings in input file")
			return nil
		}
		fmt.Fprintf(os.Stderr, "loaded %d finding(s) from %s\n", len(fs), fixFromPath)

		plans := buildAllFixPlans(fs)
		allowed := []findings.FixCategory{findings.FixSafe}
		if fixAggressive {
			allowed = append(allowed, findings.FixSemiSafe)
		}
		_, _, err = findings.RunFixes(context.Background(), plans, findings.RunOptions{
			PlanOnly:          fixPlanOnly,
			AutoYes:           fixYes,
			AllowedCategories: allowed,
		})
		return err
	},
}

func init() {
	fixCmd.Flags().StringVar(&fixFromPath, "from", "", "path to a findings JSON file (required; produced by --format json on scan/ci/forensics)")
	fixCmd.Flags().BoolVar(&fixPlanOnly, "plan", false, "describe the remediation plan for each finding without executing anything")
	fixCmd.Flags().BoolVar(&fixYes, "yes", false, "auto-apply all `safe` fixes without prompting")
	fixCmd.Flags().BoolVar(&fixAggressive, "aggressive", false, "also auto-apply `semi-safe` fixes under --yes (project-lockfile upgrades, uninstalls)")
	_ = fixCmd.MarkFlagRequired("from")
	rootCmd.AddCommand(fixCmd)
}
