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
	// v0.9–v0.14 ecosystems (publisher metadata + sigstore-grade
	// provenance where available).
	p.Register("npm", registries.NewNPM())
	p.Register("pypi", registries.NewPyPI())
	p.Register("rubygems", registries.NewRubyGems())
	p.Register("crates", registries.NewCrates())
	p.Register("maven", registries.NewMavenCentral())
	p.Register("go", registries.NewGoMod())
	p.RegisterProvenance("npm", registries.NewNPM())
	p.RegisterProvenance("pypi", registries.NewPyPI())
	p.RegisterProvenance("go", registries.NewGoMod())
	p.RegisterProvenance("maven", registries.NewMavenCentral())
	p.RegisterProvenance("rubygems", registries.NewRubyGems())
	p.RegisterProvenance("crates", registries.NewCrates())

	// v0.16 ecosystems — version-only probes (publish time +
	// publisher, no sigstore-grade provenance). Adding these gives
	// cooldown / publisher-change / maintainer-trust coverage to
	// .NET / PHP / Dart / Erlang / Haskell / R / iOS / Python-via-
	// Conda / Perl, eliminating the bulk of pre-v0.16 "no registry
	// probe" Unknowns silenced by predictive's v0.15.3 filter.
	p.Register("nuget", registries.NewNuGet())
	p.Register("packagist", registries.NewPackagist())
	p.Register("pub", registries.NewPub())
	p.Register("hex", registries.NewHex())
	p.Register("hackage", registries.NewHackage())
	p.Register("cran", registries.NewCRAN())
	p.Register("cocoapods", registries.NewCocoaPods())
	p.Register("conda", registries.NewConda())
	p.Register("cpan", registries.NewCPAN())
	return p
}

// chdora gate is the install-time prevention layer. Where the rest of
// chdora answers "what's compromised on this machine right now?",
// `gate` answers "should this install be allowed to happen at all?".
//
// v0.9 ships these subcommands:
//   gate check <pkg>@<ver>     — run all checks on ONE package, return verdict
//   gate exec <cmd> ...         — wrap real package manager, gate the install
//   gate install                — register shims so npm/yarn/pnpm/pip route through chdora
//   gate disable                — unregister shims
//   gate status                 — show which package managers are gated

var gateCmd = &cobra.Command{
	Use:   "gate",
	Short: "Install-time supply-chain attack prevention (cooldown, OSV/MAL-*, allowlist)",
	Long: `chdora gate sits between you and the package registry. Each install
gets a layered check before bytes hit disk:

  - cooldown          refuse versions less than --cooldown old (default 72h)
  - osv-malicious     refuse packages in OpenSSF Malicious Packages feed
  - allowlist         per-project chaindora.yml allow/deny rules

Future v0.9 checks:
  - publisher-change  refuse if account differs from last trusted version
  - static-pattern    refuse on obfuscation / eval(dynamic) / new install scripts
  - version-diff      flag suspicious additions across version bumps
  - maintainer-trust  warn on brand-new accounts / single-package authors

The gate fails CLOSED: any check that can't run (network down, registry
timeout, unparseable response) treats the install as suspect. Use
--allow-offline to invert that for air-gapped environments.`,
}

var (
	gateCheckEcosystem    string
	gateCheckCooldown     time.Duration
	gateCheckLenient      bool
	gateCheckOffline      bool
	gateCheckSkipOSV      bool
	gateCheckSkipStatic   bool
	gateCheckRequireProv  bool
	gateCheckExplain      bool
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
			SkipOSV:            gateCheckSkipOSV,
			SkipStatic:         gateCheckSkipStatic,
			RequireProvenance:  gateCheckRequireProv,
			Config:             cfg,
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
		switch {
		case allow:
			os.Exit(0)
		default:
			switch verdict {
			case gate.VerdictBlock:
				os.Exit(1)
			case gate.VerdictWarn:
				os.Exit(2)
			case gate.VerdictUnknown:
				os.Exit(3)
			default:
				os.Exit(1)
			}
		}
		return nil
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
		// Short form: "<ecosystem>:<name>@<version>". Only accepted
		// when the prefix matches a known ecosystem keyword — keeps
		// real names containing colons (rare but legal in some
		// registries) from being mis-parsed.
		prefix := arg[:colon]
		if isKnownGateEcosystem(prefix) {
			ecosystem = prefix
			arg = arg[colon+1:]
		}
	}

	if ecosystem == "" {
		ecosystem = "npm"
	}

	// After prefix-stripping, the only legitimate way for a name to
	// contain '/' is the npm scope syntax (@scope/name). Anything
	// else with a slash before the @version is almost certainly a
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
	if !strings.HasPrefix(namePart, "@") && strings.Contains(namePart, "/") {
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

// isKnownGateEcosystem reports whether s matches one of the ecosystem
// keys registered in buildGateProbes. Keep in sync with the Register
// calls there; adding a new ecosystem requires touching both places.
func isKnownGateEcosystem(s string) bool {
	switch s {
	case "npm", "pypi", "go", "rubygems", "crates", "maven",
		"nuget", "packagist", "pub", "hex", "hackage", "cran",
		"cocoapods", "conda", "cpan":
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
	gateCheckCmd.Flags().StringVar(&gateCheckEcosystem, "ecosystem", "npm", "ecosystem of the package: npm|pypi|go|rubygems|crates|maven|nuget|packagist|pub|hex|hackage|cran|cocoapods|conda|cpan")
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
