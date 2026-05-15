package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/alessandro-bitetto/chaindora/internal/detectors/hostforensics"
	"github.com/alessandro-bitetto/chaindora/internal/detectors/incident"
	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/incidents"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

var (
	forensicsHome         string
	forensicsHunt         string
	forensicsJSON         bool
	forensicsSkipHunt     bool
	forensicsIncidentsDir string
)

var forensicsCmd = &cobra.Command{
	Use:   "forensics",
	Short: "Hunt for post-compromise artifacts on this machine",
	Long: `Scan host state for indicators of supply-chain compromise:

  - Stored credentials (~/.npmrc, ~/.pypirc, ~/.docker/config.json,
    ~/.aws/credentials, ~/.gem/credentials, ~/.cargo/credentials.toml)
  - Shell rc tampering (curl|bash, eval base64/curl, netcat listeners)
  - Incident-pack file artifacts hunted across a search root (default: $HOME)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		home := forensicsHome
		if home == "" {
			home, _ = os.UserHomeDir()
		}

		var all []findings.Finding

		det := hostforensics.New(home)
		results, err := det.Detect(ctx)
		if err != nil {
			return fmt.Errorf("host forensics: %w", err)
		}
		fmt.Fprintf(os.Stderr, "host-state findings: %d (home=%s)\n", len(results), home)
		all = append(all, results...)

		if !forensicsSkipHunt {
			huntRoot := forensicsHunt
			if huntRoot == "" {
				huntRoot = home
			}
			dir := incidents.ResolveDir([]string{
				forensicsIncidentsDir,
				"incidents",
				filepath.Join(home, ".chaindora", "incidents"),
			})
			if dir == "" {
				fmt.Fprintln(os.Stderr, "warn: no incident pack found; skipping artifact hunt")
			} else {
				incs, err := incidents.LoadDir(dir)
				if err != nil {
					fmt.Fprintln(os.Stderr, "warn: incident pack load failed:", err)
				} else {
					fmt.Fprintf(os.Stderr, "hunting %d incidents' file_artifacts under %s\n", len(incs), huntRoot)
					iDet := incident.New(incs)
					empty := &inventory.Inventory{}
					ires, err := iDet.Detect(ctx, empty, huntRoot)
					if err != nil {
						return fmt.Errorf("incident-pack hunt: %w", err)
					}
					all = append(all, ires...)
				}
			}
		}

		if forensicsJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(all)
		}
		renderText(all)

		if len(all) > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	forensicsCmd.Flags().StringVar(&forensicsHome, "home", "", "user home directory to inspect (default: $HOME)")
	forensicsCmd.Flags().StringVar(&forensicsHunt, "hunt-root", "", "filesystem root to hunt incident artifacts under (default: home)")
	forensicsCmd.Flags().StringVar(&forensicsIncidentsDir, "incidents", "", "path to incident-pack YAML directory")
	forensicsCmd.Flags().BoolVar(&forensicsJSON, "json", false, "emit findings as JSON")
	forensicsCmd.Flags().BoolVar(&forensicsSkipHunt, "skip-hunt", false, "skip the incident-pack file_artifact hunt")
	rootCmd.AddCommand(forensicsCmd)
}
