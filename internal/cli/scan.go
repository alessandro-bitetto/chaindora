package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

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
	jsonOut          bool
	scanFormat       string
	incidentsDir     string
	skipOSV          bool
	skipIncidents    bool
	skipHeuristic    bool
	scanFreshPopular bool
	scanExcludes     []string
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a directory tree for known-compromised supply chain components",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		root := "."
		if len(args) == 1 {
			root = args[0]
		}

		inv, err := inventory.Scan(root, inventory.WithExcludes(scanExcludes...))
		if err != nil {
			return fmt.Errorf("inventory: %w", err)
		}
		fmt.Fprintf(os.Stderr, "inventoried %d packages from %d sources\n",
			len(inv.Packages), len(inv.Sources))
		for _, e := range inv.Errors {
			fmt.Fprintln(os.Stderr, "warn:", e)
		}

		ctx := context.Background()
		var all []findings.Finding

		if !skipOSV {
			client := osv.NewClient()
			det := osvioc.New(client)
			results, err := det.Detect(ctx, inv)
			if err != nil {
				return fmt.Errorf("osv detector: %w", err)
			}
			all = append(all, results...)
		}

		if !skipIncidents {
			dir := incidents.ResolveDir([]string{
				incidentsDir,
				"incidents",
				filepath.Join(os.Getenv("HOME"), ".chaindora", "incidents"),
			})
			if dir == "" {
				fmt.Fprintln(os.Stderr, "warn: no incident pack directory found (use --incidents to specify)")
			} else {
				incs, err := incidents.LoadDir(dir)
				if err != nil {
					fmt.Fprintln(os.Stderr, "warn: incident pack load failed:", err)
				} else {
					fmt.Fprintf(os.Stderr, "loaded %d incidents from %s\n", len(incs), dir)
					det := incident.New(incs, scanExcludes...)
					results, err := det.Detect(ctx, inv, root)
					if err != nil {
						return fmt.Errorf("incident detector: %w", err)
					}
					all = append(all, results...)
				}
			}
		}

		if !skipHeuristic {
			det := heuristic.New(heuristic.Config{
				FreshPopular: heuristic.FreshPopularConfig{Enabled: scanFreshPopular},
				Excludes:     scanExcludes,
			})
			results, err := det.Detect(ctx, inv, root)
			if err != nil {
				return fmt.Errorf("heuristic detector: %w", err)
			}
			all = append(all, results...)
		}

		if err := renderFindings(os.Stdout, all, effectiveFormat(scanFormat, jsonOut)); err != nil {
			return err
		}
		if len(all) > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	scanCmd.Flags().BoolVar(&jsonOut, "json", false, "deprecated; shortcut for --format=json")
	scanCmd.Flags().StringVar(&scanFormat, "format", "text", "output format: text|json|jsonl|sarif|github")
	scanCmd.Flags().StringVar(&incidentsDir, "incidents", "", "path to incident-pack YAML directory (default: ./incidents or ~/.chaindora/incidents)")
	scanCmd.Flags().BoolVar(&skipOSV, "skip-osv", false, "skip OSV.dev queries")
	scanCmd.Flags().BoolVar(&skipIncidents, "skip-incidents", false, "skip the curated incident pack")
	scanCmd.Flags().BoolVar(&skipHeuristic, "skip-heuristic", false, "skip behavioral heuristics (unpinned refs, CI shell patterns, install scripts, typosquat, dep-confusion)")
	scanCmd.Flags().BoolVar(&scanFreshPopular, "fresh-popular", false, "also check whether popular npm/PyPI deps were published in the last 14 days (requires network)")
	scanCmd.Flags().StringSliceVar(&scanExcludes, "exclude", nil, "directory basename(s) to skip (repeatable or comma-separated, e.g. --exclude testdata,vendor)")
	rootCmd.AddCommand(scanCmd)
}
