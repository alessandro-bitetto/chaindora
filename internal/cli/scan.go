package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/alessandro-bitetto/chaindora/internal/detectors/incident"
	"github.com/alessandro-bitetto/chaindora/internal/detectors/osvioc"
	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/incidents"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
	"github.com/alessandro-bitetto/chaindora/internal/osv"
)

var (
	jsonOut       bool
	incidentsDir  string
	skipOSV       bool
	skipIncidents bool
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

		inv, err := inventory.Scan(root)
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
					det := incident.New(incs)
					results, err := det.Detect(ctx, inv, root)
					if err != nil {
						return fmt.Errorf("incident detector: %w", err)
					}
					all = append(all, results...)
				}
			}
		}

		if jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(all); err != nil {
				return err
			}
		} else {
			renderText(all)
		}

		if len(all) > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func renderText(fs []findings.Finding) {
	if len(fs) == 0 {
		fmt.Println("no known supply chain compromises detected")
		return
	}
	fmt.Printf("%d finding(s):\n\n", len(fs))
	for _, f := range fs {
		head := f.PURL
		if head == "" {
			head = f.SourcePath
		}
		fmt.Printf("  [%s] [%s] %s\n", f.Severity, f.Detector, head)
		fmt.Printf("    %s — %s\n", f.VulnID, f.Summary)
		if f.SourcePath != "" && f.SourcePath != head {
			fmt.Printf("    source: %s\n", f.SourcePath)
		}
		for _, ref := range f.References {
			fmt.Printf("    ref: %s\n", ref)
		}
		fmt.Println()
	}
}

func init() {
	scanCmd.Flags().BoolVar(&jsonOut, "json", false, "emit findings as JSON")
	scanCmd.Flags().StringVar(&incidentsDir, "incidents", "", "path to incident-pack YAML directory (default: ./incidents or ~/.chaindora/incidents)")
	scanCmd.Flags().BoolVar(&skipOSV, "skip-osv", false, "skip OSV.dev queries")
	scanCmd.Flags().BoolVar(&skipIncidents, "skip-incidents", false, "skip the curated incident pack")
	rootCmd.AddCommand(scanCmd)
}
