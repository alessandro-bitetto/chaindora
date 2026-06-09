package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// `chdora audit` is a one-word entry point for "scan everything on this
// machine." It's a thin wrapper around the forensics flow that defaults
// every opt-in detector to ON and points --scan-projects at $HOME, so a
// user who wants a comprehensive single-machine audit doesn't need to
// remember five flags.

var (
	auditRoots             []string
	auditWholeMachine      bool
	auditFormat            string
	auditIncidentsDir      string
	auditExcludes          []string
	auditSkipDeep          bool
	auditSkipPersist       bool
	auditSkipExt           bool
	auditSkipSSH           bool
	auditSkipOSV           bool
	auditSkipHeur          bool
	auditSkipHunt          bool
	auditVerbose           bool
	auditFixPlan           bool
	auditFix               bool
	auditYes               bool
	auditAggressive        bool
	auditSavePlan          bool
	auditSSHBaseline       string
	auditSkipRegistry      bool
	auditGitOnly           bool
	auditExcludeCVEs       bool
	auditExcludeSupply     bool
	auditExcludeConfig     bool
	auditExcludeHost       bool
	auditExcludePredictive bool
	auditOffline           bool
)

// wholeMachineExcludes adds curated directory-basename skips on top of the
// existing defaults (node_modules, .venv, etc.) when --whole-machine is set.
// Each entry is a basename that's matched anywhere in the tree — there are
// edge cases (a user's "Documents/System Architecture/" would also be
// skipped) but in practice these are the macOS / Linux system / virtual
// filesystem paths that contain no third-party manifests, and the cost of
// over-matching is far less than the cost of walking them.
var wholeMachineExcludes = []string{
	// macOS / FreeBSD
	"System", "private", "Volumes", "cores",
	".Spotlight-V100", ".Trashes", ".fseventsd", ".DocumentRevisions-V100",
	".TemporaryItems", ".PKInstallSandboxManager", ".PKInstallSandboxManager-SystemSoftware",
	// Linux virtual + system
	"proc", "sys", "dev", "run", "boot",
	// Network / mount points
	"net", "mnt", "media",
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run a full single-machine audit — every detector, every project under $HOME",
	Long: `Comprehensive single-machine audit. One command, all detectors:

  - Walks the filesystem under --root (default $HOME) and runs a full
    'chdora scan' against every project manifest it finds (package.json,
    requirements.txt, poetry.lock, uv.lock, Pipfile.lock, go.mod,
    Dockerfile, CI YAMLs).
  - Enumerates globally-installed packages (npm -g, pip --user/--global,
    brew, apt) and matches them against OSV + the incident pack.
  - Inventories Chromium / VSCode / Cursor extensions.
  - Lists user-level persistence (cron, launchd, systemd, Scheduled Tasks).
  - Snapshots / diffs ~/.ssh/authorized_keys against the baseline.
  - Plus the default forensics host-state checks (credential files,
    shell rc tampering, PowerShell profile, file-artifact hunt).

Equivalent to:

  chdora forensics --scan-projects <root> --deep --extensions --persistence \
                   --ssh-check --verbose

Each detector can be individually disabled with its --skip-X flag.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Resolve effective roots. --whole-machine adds "/" and the curated
		// system exclusions on top of whatever --root was given. If neither
		// --root nor --whole-machine is set, default to $HOME (single-root).
		roots := append([]string{}, auditRoots...)
		excludes := append([]string{}, auditExcludes...)
		if auditWholeMachine {
			if !containsString(roots, "/") {
				roots = append(roots, "/")
			}
			for _, e := range wholeMachineExcludes {
				if !containsString(excludes, e) {
					excludes = append(excludes, e)
				}
			}
			if os.Geteuid() != 0 && os.Geteuid() != -1 {
				fmt.Fprintln(os.Stderr, "[chdora] --whole-machine without root: some paths (other users' homes, /var, /etc) will be silently skipped. Re-run with `sudo` for full coverage.")
			}
		}
		if len(roots) == 0 {
			home, _ := os.UserHomeDir()
			roots = []string{home}
		}

		// Shared flag wiring (root-independent detectors).
		forensicsIncidentsDir = auditIncidentsDir
		forensicsFormat = auditFormat
		forensicsJSON = false
		forensicsExcludes = excludes
		forensicsVerbose = auditVerbose
		forensicsSSHBaseline = auditSSHBaseline
		forensicsDeep = !auditSkipDeep
		forensicsPersistence = !auditSkipPersist
		forensicsExtensions = !auditSkipExt
		forensicsSSHCheck = !auditSkipSSH
		forensicsSkipOSV = auditSkipOSV
		forensicsSkipHeur = auditSkipHeur
		forensicsSkipHunt = auditSkipHunt
		forensicsSkipRegistry = auditSkipRegistry
		forensicsGitOnly = auditGitOnly
		forensicsExcludeCVEs = auditExcludeCVEs
		forensicsExcludeSupply = auditExcludeSupply
		forensicsExcludeConfig = auditExcludeConfig
		forensicsExcludeHost = auditExcludeHost
		forensicsExcludePredictive = auditExcludePredictive
		forensicsOffline = auditOffline
		forensicsFixPlan = auditFixPlan
		forensicsFix = auditFix
		forensicsYes = auditYes
		forensicsAggressive = auditAggressive
		forensicsSavePlan = auditSavePlan

		// Single-root case: identical to before, one full flow.
		// Exception: when the root is "/" (only injected via
		// --whole-machine without explicit --root), don't conflate
		// the walk root with the host-state home — that would point
		// trustdrift / hostforensics at "/" and produce
		// "mkdir /.chaindora: read-only file system" baseline-write
		// failures instead of writing to $HOME/.chaindora/.
		if len(roots) == 1 {
			r := roots[0]
			if r == "/" {
				home, _ := os.UserHomeDir()
				forensicsHome = home
			} else {
				forensicsHome = r
			}
			forensicsHunt = r
			forensicsScanProjects = r
			return runForensicsFlow(context.Background())
		}

		// Multi-root case: run host-state-bound detectors ONCE against $HOME
		// (the first root if it equals $HOME, else $HOME); then run the
		// per-root filesystem walks for each additional root. Effectively the
		// flow we want is "audit-once, then walk every requested tree."
		home, _ := os.UserHomeDir()
		forensicsHome = home
		// First root: full flow including host-state.
		fmt.Fprintf(os.Stderr, "[chdora] auditing %d root(s): %v\n", len(roots), roots)
		forensicsHunt = roots[0]
		forensicsScanProjects = roots[0]
		if err := runForensicsFlow(context.Background()); err != nil {
			return err
		}
		// Subsequent roots: walks only (host-state already covered).
		forensicsSkipHunt = auditSkipHunt
		auditSkipDeep, auditSkipExt, auditSkipPersist, auditSkipSSH = true, true, true, true
		forensicsDeep, forensicsExtensions, forensicsPersistence, forensicsSSHCheck = false, false, false, false
		for _, r := range roots[1:] {
			fmt.Fprintf(os.Stderr, "\n[chdora] auditing additional root: %s\n", r)
			forensicsHunt = r
			forensicsScanProjects = r
			if err := runForensicsFlow(context.Background()); err != nil {
				return err
			}
		}
		return nil
	},
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func init() {
	auditCmd.Flags().StringSliceVar(&auditRoots, "root", nil,
		"filesystem root(s) to audit (default: $HOME). Repeat for multiple roots: --root /Users --root /opt --root /Applications. Used for both project discovery and the file-artifact hunt.")
	auditCmd.Flags().BoolVar(&auditWholeMachine, "whole-machine", false,
		"audit the entire filesystem ('/'). Auto-skips macOS / Linux system / virtual paths (System, private, Volumes, proc, sys, dev, ...). Recommend `sudo` for full coverage of other users' homes + /var + /etc.")
	auditCmd.Flags().StringVar(&auditFormat, "format", "text",
		"output format: text|json|jsonl|sarif|github")
	auditCmd.Flags().StringVar(&auditIncidentsDir, "incidents", "",
		"path to incident-pack YAML directory (default: ~/.chaindora/incidents, then bundled)")
	auditCmd.Flags().StringSliceVar(&auditExcludes, "exclude", nil,
		"directory basename(s) to skip during project discovery + artifact hunt")

	auditCmd.Flags().BoolVar(&auditSkipDeep, "skip-deep", false,
		"do not enumerate globally-installed packages (npm -g, pip, brew, apt)")
	auditCmd.Flags().BoolVar(&auditSkipPersist, "skip-persistence", false,
		"do not enumerate user-level persistence (cron, launchd, systemd, Scheduled Tasks)")
	auditCmd.Flags().BoolVar(&auditSkipExt, "skip-extensions", false,
		"do not enumerate browser / IDE extensions")
	auditCmd.Flags().BoolVar(&auditSkipSSH, "skip-ssh-check", false,
		"do not snapshot/diff ~/.ssh/authorized_keys")
	auditCmd.Flags().BoolVar(&auditSkipHunt, "skip-hunt", false,
		"do not walk the filesystem for incident-pack file artifacts")
	auditCmd.Flags().BoolVar(&auditSkipOSV, "skip-osv", false,
		"do not query OSV.dev (offline mode)")
	auditCmd.Flags().BoolVar(&auditSkipHeur, "skip-heuristic", false,
		"do not run behavioural heuristics on discovered projects")
	auditCmd.Flags().BoolVar(&auditSkipRegistry, "skip-registry", false,
		"do not query npm/PyPI for evidence (offline mode; dep-confusion / typosquat / install-script heuristics become silent)")
	auditCmd.Flags().BoolVar(&auditGitOnly, "git-only", false,
		"focus mode: only scan project roots inside a git work tree (repos you maintain). NOT the default — a full audit still sees downloaded / extracted / non-versioned trees, where supply-chain compromises often hide.")
	auditCmd.Flags().BoolVar(&auditExcludeCVEs, "exclude-cves", false,
		"hide the dependency-CVE section (commodity OSV CVE matches)")
	auditCmd.Flags().BoolVar(&auditExcludeSupply, "exclude-supply-chain", false,
		"hide the supply-chain attack section")
	auditCmd.Flags().BoolVar(&auditExcludeConfig, "exclude-config", false,
		"hide the configuration-risks section (unpinned action refs, curl|bash CI patterns)")
	auditCmd.Flags().BoolVar(&auditExcludeHost, "exclude-host", false,
		"hide the host-state section (credential files, shell-rc, persistence)")
	auditCmd.Flags().BoolVar(&auditExcludePredictive, "exclude-predictive", false,
		"hide the predictive-signals section (gate-style behavioral checks on installed packages)")
	auditCmd.Flags().BoolVar(&auditOffline, "offline", false,
		"no network calls — implies --skip-osv and --skip-registry. Uses only the local incident pack + cached registry data.")

	auditCmd.Flags().StringVar(&auditSSHBaseline, "ssh-baseline", "",
		"alternative path for the SSH baseline file (default ~/.chaindora/ssh-baseline.txt)")

	auditCmd.Flags().BoolVar(&auditVerbose, "verbose", false,
		"log per-project + per-host check counts to stderr")

	auditCmd.Flags().BoolVar(&auditFixPlan, "fix-plan", false,
		"after the audit, describe a remediation plan for each finding without executing anything")
	auditCmd.Flags().BoolVar(&auditFix, "fix", false,
		"after the audit, prompt to apply remediation for each finding (use --yes to auto-apply safe fixes)")
	auditCmd.Flags().BoolVar(&auditYes, "yes", false,
		"auto-apply all fixes classified `safe` without prompting (requires --fix)")
	auditCmd.Flags().BoolVar(&auditAggressive, "fix-aggressive", false,
		"also auto-apply `semi-safe` fixes under --yes")
	auditCmd.Flags().BoolVar(&auditSavePlan, "save-plan", false,
		"save the generated fix-plan to ~/.chaindora/fix-plans/ and print its ID")

	rootCmd.AddCommand(auditCmd)
}
