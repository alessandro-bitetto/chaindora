package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/alessandro-bitetto/chaindora/internal/detectors/hostforensics"
	"github.com/alessandro-bitetto/chaindora/internal/detectors/incident"
	"github.com/alessandro-bitetto/chaindora/internal/detectors/trustdrift"
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
	forensicsFixPlan      bool
	forensicsFix          bool
	forensicsYes          bool
	forensicsAggressive   bool
	forensicsSavePlan     bool
	// v0.11 trust-anchor drift
	forensicsSkipTrustDrift          bool
	forensicsTrustDriftUpdateBaseline bool
	forensicsSkipRegistry bool
	forensicsExcludeCVEs   bool
	forensicsExcludeSupply bool
	forensicsExcludeConfig bool
	forensicsExcludeHost   bool
	forensicsOffline       bool
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
		return runForensicsFlow(context.Background())
	},
}

// runForensicsFlow is the shared body for the `forensics` and `audit` commands.
// It reads the forensics-* package-level flag vars; callers configure those
// before invoking. The audit command is a thin wrapper that defaults the
// opt-in detectors (--deep / --extensions / --persistence / --ssh-check) to
// true and points --scan-projects at the user's home.
func runForensicsFlow(ctx context.Context) error {
	if forensicsOffline {
		forensicsSkipOSV = true
		forensicsSkipRegistry = true
	}
	{
		home := forensicsHome
		if home == "" {
			home, _ = os.UserHomeDir()
		}

		var all []findings.Finding
		tally := newDetectorTally()

		// Always-on host-state detector. Enable up front so the
		// summary row shows even with 0 findings (which is the
		// reassuring case — no leaked credentials).
		tally.Enable("hostforensics")
		det := hostforensics.New(home)
		results, err := det.Detect(ctx)
		if err != nil {
			return fmt.Errorf("host forensics: %w", err)
		}
		tally.AbsorbFindings(results)
		all = append(all, results...)

		// Trust-anchor drift — high-leverage check per the threat
		// model. Baselines on first run, alerts on subsequent
		// drift. Content-aware warnings fire even on first run
		// for high-risk shapes (.npmrc redirected away from
		// canonical registry, git insteadOf rewrites, etc.).
		if !forensicsSkipTrustDrift {
			trustDet := trustdrift.New(home)
			trustDet.UpdateBaseline = forensicsTrustDriftUpdateBaseline
			tdResults, terr := trustDet.Detect(ctx)
			if terr != nil {
				fmt.Fprintf(os.Stderr, "warn: trust-drift: %v\n", terr)
			} else {
				tally.AbsorbFindings(tdResults)
				all = append(all, tdResults...)
			}
		}

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
					tally.Enable("incident-pack")
					iDet := incident.New(incs, forensicsExcludes...)
					empty := &inventory.Inventory{}
					ires, err := iDet.Detect(ctx, empty, huntRoot)
					if err != nil {
						return fmt.Errorf("incident-pack hunt: %w", err)
					}
					tally.AbsorbFindings(ires)
					all = append(all, ires...)
				}
			}
		}

		// Shared registry probes for every per-project + per-source
		// scan below. Built once so the disk cache amortizes.
		npmProbe, pypiProbe := buildRegistryProbes(forensicsSkipRegistry)

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
				NPMProbe:      npmProbe,
				PyPIProbe:     pypiProbe,
			}
			// Per-project scans run osv-ioc / incident-pack /
			// heuristic depending on opts.Skip* flags. Mark every
			// enabled detector so they show up in the summary
			// even when 0 projects yield findings.
			if !opts.SkipOSV {
				tally.Enable("osv-ioc")
			}
			if !opts.SkipIncidents {
				tally.Enable("incident-pack")
			}
			if !opts.SkipHeuristic {
				tally.Enable("heuristic")
			}
			for _, r := range roots {
				results, err := scanProject(ctx, r, opts)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warn: %s: %v\n", r, err)
					continue
				}
				tally.AbsorbFindings(results)
				all = append(all, results...)
			}
		}

		if forensicsSSHCheck {
			sshResults := hostforensics.ScanSSHAuthorizedKeys(home, forensicsSSHBaseline)
			if forensicsVerbose {
				fmt.Fprintf(os.Stderr, "ssh-check: %d finding(s)\n", len(sshResults))
			}
			tally.AbsorbFindings(sshResults)
			all = append(all, sshResults...)
		}

		if forensicsPersistence {
			persistenceResults := hostforensics.ScanPersistence(home)
			if forensicsVerbose {
				fmt.Fprintf(os.Stderr, "persistence: %d finding(s)\n", len(persistenceResults))
			}
			tally.AbsorbFindings(persistenceResults)
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
				tally.AbsorbFindings(results)
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
				NPMProbe:      npmProbe,
				PyPIProbe:     pypiProbe,
				Excludes:      forensicsExcludes,
				PreInventory:  globalInv,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: deep scan: %v\n", err)
			} else {
				tally.AbsorbFindings(results)
				all = append(all, results...)
			}
		}

		// Per-detector summary on stderr before the findings list
		// goes to stdout. Replaces the v0.5.x inline "host-state
		// findings: 0" pattern that looked like "0 findings overall"
		// without context.
		tally.Print(os.Stderr)

		ExcludeCVEs = forensicsExcludeCVEs
		ExcludeSupplyChain = forensicsExcludeSupply
		ExcludeConfig = forensicsExcludeConfig
		ExcludeHost = forensicsExcludeHost
		if err := renderFindings(os.Stdout, all, effectiveFormat(forensicsFormat, forensicsJSON)); err != nil {
			return err
		}

		plans := buildAllFixPlans(all)
		var savedID string
		if forensicsSavePlan && len(plans) > 0 {
			scanRoot := forensicsScanProjects
			if scanRoot == "" {
				scanRoot = forensicsHome
			}
			id, sErr := saveFixPlan(plans, len(all), scanRoot)
			if sErr != nil {
				return fmt.Errorf("save plan: %w", sErr)
			}
			savedID = id
		}
		if forensicsFixPlan || forensicsFix {
			allowed := []findings.FixCategory{findings.FixSafe}
			if forensicsAggressive {
				allowed = append(allowed, findings.FixSemiSafe)
			}
			_, _, fErr := findings.RunFixes(ctx, plans, findings.RunOptions{
				PlanOnly:          forensicsFixPlan && !forensicsFix,
				AutoYes:           forensicsYes,
				AllowedCategories: allowed,
			})
			if fErr != nil {
				return fErr
			}
		}
		saved := forensicsSavePlan && savedID != ""
		fixRequested := forensicsFixPlan || forensicsFix
		if !saved && !fixRequested {
			scanRoot := forensicsScanProjects
			if scanRoot == "" {
				scanRoot = forensicsHome
			}
			if id := maybePromptSavePlan(os.Stdin, os.Stderr, plans, len(all), scanRoot, saved, fixRequested); id != "" {
				saved = true
				savedID = id
			}
		}
		emitEndOfRunFooter(os.Stderr, plans, saved, savedID, fixRequested)

		if len(all) > 0 {
			os.Exit(1)
		}
		return nil
	}
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
	forensicsCmd.Flags().BoolVar(&forensicsFixPlan, "fix-plan", false, "describe a remediation plan for each finding without executing anything")
	forensicsCmd.Flags().BoolVar(&forensicsFix, "fix", false, "after scanning, prompt to apply remediation for each finding (use --yes to auto-apply safe fixes)")
	forensicsCmd.Flags().BoolVar(&forensicsYes, "yes", false, "auto-apply all fixes classified `safe` without prompting (requires --fix)")
	forensicsCmd.Flags().BoolVar(&forensicsAggressive, "fix-aggressive", false, "also auto-apply `semi-safe` fixes under --yes")
	forensicsCmd.Flags().BoolVar(&forensicsSavePlan, "save-plan", false, "save the generated fix-plan to ~/.chaindora/fix-plans/ and print its ID")
	forensicsCmd.Flags().BoolVar(&forensicsSkipTrustDrift, "skip-trust-drift", false, "skip the trust-anchor drift check (.npmrc registry, .gitconfig insteadOf, CA store, etc.)")
	forensicsCmd.Flags().BoolVar(&forensicsTrustDriftUpdateBaseline, "trust-drift-update-baseline", false, "rewrite the trust-drift baseline to current state — use after intentional registry/config changes")
	forensicsCmd.Flags().BoolVar(&forensicsSkipRegistry, "skip-registry", false, "do not query npm/PyPI for evidence (offline mode; dep-confusion / typosquat / install-script heuristics become silent)")
	forensicsCmd.Flags().BoolVar(&forensicsExcludeCVEs, "exclude-cves", false, "hide the dependency-CVE section")
	forensicsCmd.Flags().BoolVar(&forensicsExcludeSupply, "exclude-supply-chain", false, "hide the supply-chain attack section")
	forensicsCmd.Flags().BoolVar(&forensicsExcludeConfig, "exclude-config", false, "hide the configuration-risks section")
	forensicsCmd.Flags().BoolVar(&forensicsExcludeHost, "exclude-host", false, "hide the host-state section")
	forensicsCmd.Flags().BoolVar(&forensicsOffline, "offline", false, "no network calls — implies --skip-osv and --skip-registry")
	rootCmd.AddCommand(forensicsCmd)
}
