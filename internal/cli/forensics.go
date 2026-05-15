package cli

import (
	"context"
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
	forensicsFormat       string
	forensicsSkipHunt     bool
	forensicsIncidentsDir string
	forensicsScanProjects string
	forensicsSkipOSV      bool
	forensicsSkipHeur     bool
	forensicsVerbose      bool
	forensicsExcludes     []string
	forensicsDeep         bool
	forensicsSSHCheck     bool
	forensicsSSHBaseline  string
	forensicsPersistence  bool
	forensicsExtensions   bool
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
					iDet := incident.New(incs, forensicsExcludes...)
					empty := &inventory.Inventory{}
					ires, err := iDet.Detect(ctx, empty, huntRoot)
					if err != nil {
						return fmt.Errorf("incident-pack hunt: %w", err)
					}
					all = append(all, ires...)
				}
			}
		}

		if forensicsScanProjects != "" {
			projRoot := forensicsScanProjects
			if forensicsVerbose {
				fmt.Fprintf(os.Stderr, "discovering projects under %s\n", projRoot)
			}
			roots := discoverProjects(projRoot, mergeExcludeMap(forensicsExcludes))
			fmt.Fprintf(os.Stderr, "found %d project root(s) under %s\n", len(roots), projRoot)
			opts := projectScanOpts{
				IncidentsDir:  forensicsIncidentsDir,
				SkipOSV:       forensicsSkipOSV,
				SkipIncidents: false,
				SkipHeuristic: forensicsSkipHeur,
				FreshPopular:  false,
				Verbose:       forensicsVerbose,
				Excludes:      forensicsExcludes,
			}
			for _, r := range roots {
				results, err := scanProject(ctx, r, opts)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warn: %s: %v\n", r, err)
					continue
				}
				all = append(all, results...)
			}
		}

		if forensicsSSHCheck {
			sshResults := hostforensics.ScanSSHAuthorizedKeys(home, forensicsSSHBaseline)
			if forensicsVerbose {
				fmt.Fprintf(os.Stderr, "ssh-check: %d finding(s)\n", len(sshResults))
			}
			all = append(all, sshResults...)
		}

		if forensicsPersistence {
			persistenceResults := hostforensics.ScanPersistence(home)
			if forensicsVerbose {
				fmt.Fprintf(os.Stderr, "persistence: %d finding(s)\n", len(persistenceResults))
			}
			all = append(all, persistenceResults...)
		}

		if forensicsExtensions {
			extInv := hostforensics.ScanExtensions(home)
			if forensicsVerbose {
				fmt.Fprintf(os.Stderr, "extensions: %d package(s) across %d source(s)\n",
					len(extInv.Packages), len(extInv.Sources))
			}
			results, err := scanProject(ctx, "", projectScanOpts{
				IncidentsDir:  forensicsIncidentsDir,
				SkipOSV:       true, // OSV doesn't catalog browser/IDE extensions
				SkipIncidents: false,
				SkipHeuristic: true, // unpinned/install-script don't apply
				Verbose:       forensicsVerbose,
				Excludes:      forensicsExcludes,
				PreInventory:  extInv,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: extensions scan: %v\n", err)
			} else {
				all = append(all, results...)
			}
		}

		if forensicsDeep {
			if forensicsVerbose {
				fmt.Fprintln(os.Stderr, "enumerating globally-installed packages")
			}
			globalInv := hostforensics.ScanGlobalPackages()
			if forensicsVerbose {
				fmt.Fprintf(os.Stderr, "global packages: %d (sources: %d)\n",
					len(globalInv.Packages), len(globalInv.Sources))
			}
			results, err := scanProject(ctx, "", projectScanOpts{
				IncidentsDir:  forensicsIncidentsDir,
				SkipOSV:       forensicsSkipOSV,
				SkipIncidents: false,
				SkipHeuristic: forensicsSkipHeur,
				FreshPopular:  false,
				Verbose:       forensicsVerbose,
				Excludes:      forensicsExcludes,
				PreInventory:  globalInv,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: deep scan: %v\n", err)
			} else {
				all = append(all, results...)
			}
		}

		if err := renderFindings(os.Stdout, all, effectiveFormat(forensicsFormat, forensicsJSON)); err != nil {
			return err
		}
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
	forensicsCmd.Flags().BoolVar(&forensicsJSON, "json", false, "deprecated; shortcut for --format=json")
	forensicsCmd.Flags().StringVar(&forensicsFormat, "format", "text", "output format: text|json|jsonl|sarif|github")
	forensicsCmd.Flags().BoolVar(&forensicsSkipHunt, "skip-hunt", false, "skip the incident-pack file_artifact hunt")
	forensicsCmd.Flags().StringVar(&forensicsScanProjects, "scan-projects", "",
		"also walk this directory for project manifests (package.json, requirements.txt, Dockerfile, etc.) and run a full scan on each project root found")
	forensicsCmd.Flags().BoolVar(&forensicsSkipOSV, "skip-osv", false, "skip OSV.dev queries during --scan-projects")
	forensicsCmd.Flags().BoolVar(&forensicsSkipHeur, "skip-heuristic", false, "skip behavioral heuristics during --scan-projects")
	forensicsCmd.Flags().BoolVar(&forensicsVerbose, "verbose", false, "log per-project scanned + per-host check counts to stderr")
	forensicsCmd.Flags().StringSliceVar(&forensicsExcludes, "exclude", nil, "directory basename(s) to skip during the hunt / project scans")
	forensicsCmd.Flags().BoolVar(&forensicsDeep, "deep", false, "also enumerate globally-installed packages (npm -g, pip) and run the detector pipeline against them")
	forensicsCmd.Flags().BoolVar(&forensicsSSHCheck, "ssh-check", false, "snapshot/diff ~/.ssh/authorized_keys against ~/.chaindora/ssh-baseline.txt; first run creates the baseline, subsequent runs flag added (HIGH) or removed (MEDIUM) keys")
	forensicsCmd.Flags().StringVar(&forensicsSSHBaseline, "ssh-baseline", "", "alternative path for the SSH baseline file (default ~/.chaindora/ssh-baseline.txt)")
	forensicsCmd.Flags().BoolVar(&forensicsPersistence, "persistence", false, "enumerate user-level persistence (cron, launchd, systemd, Scheduled Tasks); flag entries whose command matches a malware pattern as HIGH")
	forensicsCmd.Flags().BoolVar(&forensicsExtensions, "extensions", false, "enumerate installed Chromium-based browser extensions and VSCode/Cursor extensions; match against the incident pack")
	rootCmd.AddCommand(forensicsCmd)
}
