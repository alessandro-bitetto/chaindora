package cli

import (
	"context"
	"os"

	"github.com/spf13/cobra"
)

// `chdora audit` is a one-word entry point for "scan everything on this
// machine." It's a thin wrapper around the forensics flow that defaults
// every opt-in detector to ON and points --scan-projects at $HOME, so a
// user who wants a comprehensive single-machine audit doesn't need to
// remember five flags.

var (
	auditRoot          string
	auditFormat        string
	auditIncidentsDir  string
	auditExcludes      []string
	auditSkipDeep      bool
	auditSkipPersist   bool
	auditSkipExt       bool
	auditSkipSSH       bool
	auditSkipOSV       bool
	auditSkipHeur      bool
	auditSkipHunt      bool
	auditVerbose       bool
	auditFixPlan       bool
	auditFix           bool
	auditYes           bool
	auditAggressive    bool
	auditSSHBaseline   string
)

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
		// Wire audit's own flags into the shared forensics-* package vars
		// that runForensicsFlow reads. Audit's defaults are the inverse of
		// forensics': everything ON unless explicitly --skip-X'd.
		root := auditRoot
		if root == "" {
			root, _ = os.UserHomeDir()
		}
		forensicsHome = root
		forensicsHunt = root
		forensicsScanProjects = root
		forensicsIncidentsDir = auditIncidentsDir
		forensicsFormat = auditFormat
		forensicsJSON = false
		forensicsExcludes = auditExcludes
		forensicsVerbose = auditVerbose
		forensicsSSHBaseline = auditSSHBaseline

		// Inverted opt-in flags.
		forensicsDeep = !auditSkipDeep
		forensicsPersistence = !auditSkipPersist
		forensicsExtensions = !auditSkipExt
		forensicsSSHCheck = !auditSkipSSH

		// Forwarded skip flags.
		forensicsSkipOSV = auditSkipOSV
		forensicsSkipHeur = auditSkipHeur
		forensicsSkipHunt = auditSkipHunt

		// Fix-flow forwarding.
		forensicsFixPlan = auditFixPlan
		forensicsFix = auditFix
		forensicsYes = auditYes
		forensicsAggressive = auditAggressive

		return runForensicsFlow(context.Background())
	},
}

func init() {
	auditCmd.Flags().StringVar(&auditRoot, "root", "",
		"filesystem root to audit (default: $HOME). Used for both project discovery and the file-artifact hunt.")
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

	rootCmd.AddCommand(auditCmd)
}
