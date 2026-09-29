package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/alessandro-bitetto/chaindora/internal/gate"
	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

// buildGateProbes returns the canonical Probes table with every
// ecosystem chaindora knows about wired in. The seam between
// HTTP-backed registries and the gate's per-ecosystem interface.
// Add a new ecosystem here once it has a registries.Probe
// implementation, and every gate checker picks it up.
func buildGateProbes() *gate.Probes {
	p := gate.NewProbes()
	p.Register("npm", registries.NewNPM())
	p.Register("pypi", registries.NewPyPI())
	p.Register("nuget", registries.NewNuGet())
	p.Register("go", registries.NewGoMod())
	p.Register("crates", registries.NewCrates())
	p.RegisterProvenance("npm", registries.NewNPM())
	p.RegisterProvenance("pypi", registries.NewPyPI())
	p.RegisterProvenance("go", registries.NewGoMod())
	p.RegisterProvenance("crates", registries.NewCrates())
	return p
}

// chdora gate is the install-time prevention layer. Where the rest of
// chdora answers "what's compromised on this machine right now?",
// `gate` answers "should this install be allowed to happen at all?".
//
// Gate subcommands:
//   gate check <pkg>@<ver>     — run all checks on ONE package, return verdict
//   gate exec <cmd> ...         — wrap real package manager, gate the install
//   gate install                — register shims so npm/yarn/pnpm/pip route through chdora
//   gate disable                — unregister shims
//   gate status                 — show which package managers are gated

var gateCmd = &cobra.Command{
	Use:   "gate",
	Short: "Install-time supply-chain attack prevention (cooldown, OSV/MAL-*, allowlist)",
	Long: `chdora gate checks packages before handing selected install commands to
npm/PyPI/.NET/Go/Rust package managers, including supported alternatives.

Checks include cooldown, known-malicious advisories, allow/deny policy,
publisher changes, maintainer history, source patterns, version differences
and provenance signals. Coverage and available metadata vary by ecosystem.

Strict policy refuses Block, Warn and Unknown results. --lenient permits
warnings; --allow-offline separately permits incomplete checks. Block always
wins. These overrides reduce protection.

The gate is not a sandbox or a guarantee that the executed install uses the
same bytes that were inspected. Some command forms pass through. Read
README.md#supported-scope and docs/threat-model.md for the boundaries.`,
}

var (
	gateCheckEcosystem   string
	gateCheckCooldown    time.Duration
	gateCheckLenient     bool
	gateCheckOffline     bool
	gateCheckSkipOSV     bool
	gateCheckSkipStatic  bool
	gateCheckRequireProv bool
	gateCheckExplain     bool
)

var gateCheckCmd = &cobra.Command{
	Use:   "check <pkg>@<version>",
	Short: "Run all gate checks against a single package",
	Long: `Run every gate-time check against one (pkg, version). Exit codes:

  0   approve — install would be allowed
  1   block   — install would be refused
  2   warn    — suspicious; allowed under --lenient, blocked otherwise
  3   unknown — checks couldn't complete; treated as block by default

Examples:

  chdora gate check lodash@4.17.21
  chdora gate check shai-hulud-payload@1.0.0       # exit 1 (MAL-* match)
  chdora gate check just-published@0.1.0           # exit 1 (cooldown)
  chdora gate check requests@2.32.0 --ecosystem pypi
  chdora gate check x@1.0 --explain                # show full reasoning`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ref, err := parsePackageArg(args[0], gateCheckEcosystem)
		if err != nil {
			return err
		}

		// Load chaindora.yml from cwd (if present). Used to:
		//  - read per-project cooldown override
		//  - read allow/deny lists
		//  - read policy flags (allow_on_warn, allow_on_unknown)
		cwd, _ := os.Getwd()
		cfg, err := gate.LoadConfig(cwd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: chaindora.yml: %v\n", err)
		}

		// Build the checker stack.
		threshold := cfg.CooldownThreshold(gateCheckCooldown)
		if gateCheckCooldown != 0 {
			threshold = gateCheckCooldown
		}
		probes := buildGateProbes()
		checkers := buildCheckerStack(probes, threshold, checkerOpts{
			SkipOSV:           gateCheckSkipOSV,
			SkipStatic:        gateCheckSkipStatic,
			RequireProvenance: gateCheckRequireProv,
			Config:            cfg,
		})

		// Resolve policy.
		policy := cfg.Policy()
		if gateCheckLenient {
			policy.AllowOnWarn = true
		}
		if gateCheckOffline {
			policy.AllowOnUnknown = true
		}

		results := gate.Run(context.Background(), checkers, []gate.PackageRef{ref})
		if len(results) != 1 {
			return fmt.Errorf("internal: expected 1 result, got %d", len(results))
		}
		pc := results[0]

		// Render per-check verdict to stderr; the exit code is the
		// machine-readable answer. Stdout reserved for future
		// --format=json.
		renderGateCheck(os.Stderr, pc, gateCheckExplain)

		allow, verdict := policy.Decide(pc)
		if allow {
			return nil // exit 0
		}
		switch verdict {
		case gate.VerdictBlock:
			return SilentExit(1)
		case gate.VerdictWarn:
			return SilentExit(2)
		case gate.VerdictUnknown:
			return SilentExit(3)
		default:
			return SilentExit(1)
		}
	},
}

// parsePackageArg accepts:
//
//	"name@version"             → PackageRef{Name: name, Version: version}
//	"@scope/name@ver"          → PackageRef{Name: @scope/name, Version: ver}
//	"pkg:<eco>/<name>@<ver>"   → PURL syntax; ecosystem derived from <eco>
//	"<eco>:<name>@<ver>"       → short ecosystem-prefixed form (e.g. "npm:lodash@4.17.21")
//
// Returns an error on:
//   - empty input
//   - missing @version
//   - a non-scoped name containing '/' (e.g. "npm/express@1.0.0" — a
//     common typo that previously fell through to the registry as a
//     literal name and produced HTTP 405)
func parsePackageArg(arg, ecosystem string) (gate.PackageRef, error) {
	if arg == "" {
		return gate.PackageRef{}, fmt.Errorf("empty package spec")
	}

	// PURL: pkg:<ecosystem>/<name>@<version>. In PURL syntax the
	// npm scope's '@' and '/' separators are URL-encoded as %40
	// and %2F. We only decode those two characters — full
	// url.QueryUnescape would decode '%40' inside a version too,
	// which would confuse the @version split below.
	if strings.HasPrefix(arg, "pkg:") {
		rest := strings.TrimPrefix(arg, "pkg:")
		slash := strings.Index(rest, "/")
		if slash <= 0 {
			return gate.PackageRef{}, fmt.Errorf("malformed PURL %q: expected pkg:<ecosystem>/<name>@<version>", arg)
		}
		ecosystem = rest[:slash]
		arg = rest[slash+1:]
		if at := strings.LastIndex(arg, "@"); at > 0 {
			name, version := arg[:at], arg[at+1:]
			name = strings.ReplaceAll(name, "%2F", "/")
			name = strings.ReplaceAll(name, "%2f", "/")
			name = strings.ReplaceAll(name, "%40", "@")
			arg = name + "@" + version
		}
	} else if colon := strings.Index(arg, ":"); colon > 0 {
		// Short form: "<ecosystem>:<name>@<version>". Validate the
		// prefix below, including retired or misspelled ecosystems.
		ecosystem = arg[:colon]
		arg = arg[colon+1:]
	}

	if ecosystem == "" {
		ecosystem = "npm"
	}

	ecosystem = canonicalGateEcosystem(ecosystem)
	if !isKnownGateEcosystem(ecosystem) {
		return gate.PackageRef{}, fmt.Errorf("unsupported ecosystem %q: use npm, pypi, nuget, go, or crates", ecosystem)
	}

	// Go module paths and npm scopes may contain '/'. In other
	// unscoped names, a slash before @version is usually a
	// typo (e.g. "npm/express@1.0.0") that previously slipped through
	// to the registry as a literal name and returned HTTP 405.
	namePart := arg
	if at := strings.Index(arg, "@"); at >= 0 {
		if strings.HasPrefix(arg, "@") {
			if i := strings.Index(arg[1:], "@"); i >= 0 {
				namePart = arg[:i+1]
			}
		} else {
			namePart = arg[:at]
		}
	}
	if ecosystem != "go" && !strings.HasPrefix(namePart, "@") && strings.Contains(namePart, "/") {
		// The common shape of this typo is "<eco>/<name>@<ver>" —
		// suggest "<eco>:<name>@<ver>" which is the supported short
		// form. If the first segment isn't a known ecosystem the
		// caller probably meant a literal scoped name; we still
		// reject (npm scopes start with '@'), but the hint is less
		// confident.
		suggestion := ""
		if i := strings.Index(namePart, "/"); i >= 0 {
			firstSegment := namePart[:i]
			if isKnownGateEcosystem(firstSegment) {
				suggestion = fmt.Sprintf(`; did you mean "%s:%s"?`, firstSegment, arg[i+1:])
			}
		}
		return gate.PackageRef{}, fmt.Errorf(
			"package name %q contains '/' but is not a scoped name%s", namePart, suggestion)
	}

	// Find the version @ — skip the leading scope @ if present.
	atIdx := -1
	if strings.HasPrefix(arg, "@") {
		if i := strings.Index(arg[1:], "@"); i >= 0 {
			atIdx = i + 1
		}
	} else {
		atIdx = strings.Index(arg, "@")
	}
	if atIdx < 0 {
		return gate.PackageRef{}, fmt.Errorf("package spec %q missing @version (gate needs a resolved version)", arg)
	}
	return gate.PackageRef{
		Ecosystem: ecosystem,
		Name:      arg[:atIdx],
		Version:   arg[atIdx+1:],
		Direct:    true,
	}, nil
}

func canonicalGateEcosystem(s string) string {
	switch strings.ToLower(s) {
	case "golang":
		return "go"
	case "cargo", "rust", "crates.io":
		return "crates"
	case "pip":
		return "pypi"
	case "dotnet":
		return "nuget"
	}
	return strings.ToLower(s)
}

// isKnownGateEcosystem reports whether s matches one of the ecosystem
// keys registered in buildGateProbes. Keep in sync with the Register
// calls there; adding a new ecosystem requires touching both places.
func isKnownGateEcosystem(s string) bool {
	switch s {
	case "npm", "pypi", "nuget", "go", "crates":
		return true
	}
	return false
}

func renderGateCheck(w *os.File, pc gate.PackageCheck, explain bool) {
	fmt.Fprintf(w, "\nchdora gate check: %s\n", pc.Package)
	for _, r := range pc.Results {
		icon := "  ok  "
		switch r.Verdict {
		case gate.VerdictBlock:
			icon = "  !!  "
		case gate.VerdictWarn:
			icon = "  ?   "
		case gate.VerdictUnknown:
			icon = "  -   "
		}
		fmt.Fprintf(w, "%s[%s] %s — %s\n", icon, r.Checker, r.Verdict, r.Reason)
		if explain && r.Detail != "" {
			for _, line := range strings.Split(r.Detail, "\n") {
				fmt.Fprintf(w, "      %s\n", line)
			}
		}
	}
	fmt.Fprintf(w, "\ndecision: %s\n", pc.Decision())
}

func init() {
	gateCheckCmd.Flags().StringVar(&gateCheckEcosystem, "ecosystem", "npm", "ecosystem of the package: npm|pypi|nuget|go|crates")
	gateCheckCmd.Flags().DurationVar(&gateCheckCooldown, "cooldown", 0, "minimum age a version must have before install is allowed (default: 72h, overridable in chaindora.yml)")
	gateCheckCmd.Flags().BoolVar(&gateCheckLenient, "lenient", false, "treat Warn verdicts as approve (still block Block)")
	gateCheckCmd.Flags().BoolVar(&gateCheckOffline, "allow-offline", false, "treat Unknown verdicts (registry unreachable) as approve — disables fail-closed posture")
	gateCheckCmd.Flags().BoolVar(&gateCheckSkipOSV, "skip-osv", false, "skip the OSV/MAL-* query")
	gateCheckCmd.Flags().BoolVar(&gateCheckSkipStatic, "skip-static", false, "skip the tarball-download static-pattern + version-diff checks (faster, less coverage)")
	gateCheckCmd.Flags().BoolVar(&gateCheckRequireProv, "require-provenance", false, "block any package missing sigstore provenance (strict mode; default warns only on regression)")
	gateCheckCmd.Flags().BoolVar(&gateCheckExplain, "explain", false, "show CheckResult.Detail context lines (publisher email, parsed advisories, etc.)")

	gateCmd.AddCommand(gateCheckCmd)
	rootCmd.AddCommand(gateCmd)
}
