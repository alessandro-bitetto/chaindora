package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/alessandro-bitetto/chaindora/internal/gate"
)

// chdora gate exec <package-manager> <args...> is the heart of the
// prevention story: resolve the full install tree the user would
// have produced, run every check against every node, and only
// hand control off to the real package manager if every node is
// approved.
//
// Today we support `npm install` / `npm i` / `npm add` (alias).
// pip / yarn / pnpm will follow once the resolver lands for them.

var (
	gateExecCooldown   time.Duration
	gateExecLenient    bool
	gateExecOffline    bool
	gateExecSkipOSV    bool
	gateExecSkipStatic bool
	gateExecExplain    bool
	gateExecDryRun     bool
)

var gateExecCmd = &cobra.Command{
	Use:   "exec [--gate-flags...] <package-manager> <args...>",
	Short: "Resolve the install tree, gate every node, then exec the real package manager",
	Long: `Wraps a package manager invocation. The flow:

  1. Resolve the FULL install tree (direct + transitive) the supplied
     args would produce, without executing any postinstall scripts.
  2. Run every gate check (cooldown, osv-malicious, allowlist, ...)
     against every node in the tree.
  3. If every node Approves under the configured policy, exec the
     real package manager with the original args.
  4. If any node fails, refuse — print which package(s) and why.

Flag handling. ` + "`gate exec`" + ` is special — it has to pass arbitrary
flags through to the wrapped package manager (npm has hundreds of
flags). Anything BEFORE the package manager name is a chdora gate
flag; everything AFTER is forwarded verbatim:

  chdora gate exec --lenient npm install --dry-run --save-dev lodash@4
   ^^^^^^^^^^^^^^^^         ^^^^ everything past here goes to npm

Currently supports: npm install / npm i / npm add. Other package
managers and verbs pass through ungated.

Examples:

  chdora gate exec npm install lodash@4.17.21
  chdora gate exec --lenient npm install left-pad
  chdora gate exec --dry-run npm install request   # gate report only`,
	// We manage our own flag parsing — cobra would otherwise eat
	// any `--*` flag the user types intending it for npm (e.g.
	// ` --save-dev`, `--dry-run`, `--global`).
	DisableFlagParsing: true,
	Args:               cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		chdoraArgs, pmArgs, err := splitGateExecArgs(args)
		if err != nil {
			return err
		}
		if len(pmArgs) == 0 {
			return fmt.Errorf("usage: chdora gate exec [--gate-flags...] <package-manager> <args...>")
		}
		if err := applyGateExecFlags(chdoraArgs); err != nil {
			return err
		}
		pm := pmArgs[0]
		pmArgs = pmArgs[1:]

		// Supported package managers route through their own
		// resolver; everything else passes through unchanged so
		// the shim is always safe to install for the user's full
		// set of package managers.
		realBin, err := findRealPackageManager(pm)
		if err != nil {
			return err
		}
		// Capture cwd here so the gradle resolver's closure can
		// see it. Other resolvers operate from a synthetic temp
		// dir and don't read cwd directly.
		cwd, _ := os.Getwd()
		var resolve func(context.Context, string, []string) ([]gate.PackageRef, error)
		var resolveUpdateAll func(context.Context, string, string) ([]gate.PackageRef, error)
		switch pm {
		case "npm":
			resolve = gate.ResolveNPMTree
			resolveUpdateAll = gate.ResolveNPMUpdateAll
		case "yarn":
			resolve = gate.ResolveYarnTree
			resolveUpdateAll = gate.ResolveYarnUpdateAll
		case "pnpm":
			resolve = gate.ResolvePnpmTree
			resolveUpdateAll = gate.ResolvePnpmUpdateAll
		case "pip", "pip3":
			resolve = gate.ResolvePipTree
		case "cargo":
			resolve = gate.ResolveCargoTree
			resolveUpdateAll = gate.ResolveCargoUpdateAll
		case "bundle":
			resolve = gate.ResolveBundlerTree
			resolveUpdateAll = gate.ResolveBundlerUpdateAll
		case "gem":
			// `gem update` (no args) updates every system-installed
			// gem — no manifest to resolve from. Stays refused for
			// now; v0.14 may enumerate via `gem list --local`.
			resolve = gate.ResolveBundlerTree
		case "mvn":
			resolve = gate.ResolveMavenTree
		case "go":
			resolve = gate.ResolveGoModTree
		case "dotnet":
			resolve = gate.ResolveNuGetTree
		case "composer":
			resolve = gate.ResolveComposerTree
		case "poetry":
			resolve = gate.ResolvePoetryTree
		case "uv":
			resolve = gate.ResolveUVTree
		case "gradle":
			// Gradle has no install-args path — resolution operates
			// against the user's actual project. We capture cwd here
			// rather than threading it through the install-args slice.
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveGradleTree(ctx, bin, cwd)
			}
		case "pod":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveCocoaPodsTree(ctx, bin, cwd)
			}
		case "swift":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveSwiftPMTree(ctx, bin, cwd)
			}
		case "dart", "flutter":
			// Dispatch on the subverb: `pub add <pkg>` uses the
			// args-based resolver; `pub get` / `upgrade` uses the
			// cwd-based one.
			resolve = func(ctx context.Context, bin string, args []string) ([]gate.PackageRef, error) {
				if len(args) >= 2 && args[0] == "pub" && args[1] == "add" {
					return gate.ResolvePubTree(ctx, bin, args[2:])
				}
				return gate.ResolvePubFromCwd(ctx, bin, cwd)
			}
		case "mix":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveHexTree(ctx, bin, cwd)
			}
		case "bun":
			resolve = gate.ResolveBunTree
		case "conda", "mamba", "micromamba":
			resolve = gate.ResolveCondaTree
		case "brew":
			resolve = gate.ResolveBrewTree
		case "conan":
			resolve = gate.ResolveConanTree
		case "pipenv":
			resolve = gate.ResolvePipenvTree
		case "pdm":
			resolve = gate.ResolvePDMTree
		case "deno":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveDenoTree(ctx, bin, cwd)
			}
		case "stack":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveStackTree(ctx, bin, cwd)
			}
		case "cabal":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveCabalTree(ctx, bin, cwd)
			}
		case "sbt":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveSBTTree(ctx, bin, cwd)
			}
		case "opam":
			resolve = gate.ResolveOpamTree
		case "rebar3":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveRebar3Tree(ctx, bin, cwd)
			}
		case "paket":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolvePaketTree(ctx, bin, cwd)
			}
		case "vcpkg":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveVcpkgTree(ctx, bin, cwd)
			}
		case "cpanm":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveCpanTree(ctx, bin, cwd)
			}
		case "luarocks":
			resolve = gate.ResolveLuaRocksTree
		case "carthage":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveCarthageTree(ctx, bin, cwd)
			}
		case "elm":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveElmTree(ctx, bin, cwd)
			}
		case "nimble":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveNimbleTree(ctx, bin, cwd)
			}
		case "shards":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveShardsTree(ctx, bin, cwd)
			}
		case "zig":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveZigTree(ctx, bin, cwd)
			}
		case "julia":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveJuliaTree(ctx, bin, cwd)
			}
		case "R", "Rscript":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveRenvTree(ctx, bin, cwd)
			}
		default:
			return passThroughToReal(pm, pmArgs)
		}

		cfg, _ := gate.LoadConfig(cwd)

		// Build the checker stack — identical to `gate check`.
		threshold := cfg.CooldownThreshold(72 * time.Hour)
		if gateExecCooldown != 0 {
			threshold = gateExecCooldown
		}
		probes := buildGateProbes()
		checkers := buildCheckerStack(probes, threshold, checkerOpts{
			SkipOSV:    gateExecSkipOSV,
			SkipStatic: gateExecSkipStatic,
			Config:     cfg,
		})

		policy := cfg.Policy()
		if gateExecLenient {
			policy.AllowOnWarn = true
		}
		if gateExecOffline {
			policy.AllowOnUnknown = true
		}

		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		var refs []gate.PackageRef
		switch classifyGateArgs(pm, pmArgs) {
		case gatePassthrough:
			return execReal(realBin, pmArgs)
		case gateRefuseUpdateAll:
			if resolveUpdateAll == nil {
				return fmt.Errorf(
					"`%s %s` with no explicit package names updates every dep in the manifest, "+
						"but chdora gate doesn't yet have an update-all resolver for %s. "+
						"Specify packages (e.g. `%s %s <pkg>`) or run with --chaindora-policy=lenient "+
						"to bypass the gate for this invocation.",
					pm, pmArgs[0], pm, pm, pmArgs[0],
				)
			}
			fmt.Fprintf(os.Stderr, "[chdora] resolving update-all tree (%s) from %s\n", pm, cwd)
			refs, err = resolveUpdateAll(ctx, realBin, cwd)
			if err != nil {
				if pmErr := asPMError(err); pmErr != nil {
					surfacePMError(pmErr)
				}
				return fmt.Errorf("resolve update-all tree: %w", err)
			}
		case gateProceed:
			installArgs := pmArgs[1:]
			// dotnet's install verb is two tokens (`add package <id>`).
			// classifyGateArgs already keyed on both, but the args
			// slice still carries the "package" subcommand token —
			// strip it so the resolver sees just the package names.
			if pm == "dotnet" && len(installArgs) > 0 && installArgs[0] == "package" {
				installArgs = installArgs[1:]
			}
			// Cwd-only PMs (gradle/pod/swift/mix and the dart-pub-cwd
			// path) have no install-args contract — the user's manifest
			// is the input. Skip the no-args passthrough other PMs use
			// for `npm install` (lockfile restore from vetted state).
			if !isPMCwdOnly(pm) {
				// Skip the gate when EVERY install arg is a flag (no real
				// packages to vet). `npm install --save-dev` with nothing
				// after it is effectively the no-args case.
				realPkgs := 0
				for _, a := range installArgs {
					if !strings.HasPrefix(a, "-") {
						realPkgs++
					}
				}
				if realPkgs == 0 {
					return execReal(realBin, pmArgs)
				}
			}
			fmt.Fprintf(os.Stderr, "[chdora] resolving install tree (%s) for: %s\n", pm, strings.Join(pmArgs, " "))
			refs, err = resolve(ctx, realBin, installArgs)
			if err != nil {
				if pmErr := asPMError(err); pmErr != nil {
					surfacePMError(pmErr)
				}
				return fmt.Errorf("resolve tree: %w", err)
			}
		}
		fmt.Fprintf(os.Stderr, "[chdora] tree resolved: %d unique (name, version) tuple(s)\n", len(refs))

		// Gate every node. CachedRun reads from ~/.chaindora/gate-cache/
		// (per-(eco,name,version,integrity) verdicts, TTL 7 days for
		// Approve-only) and inserts a republish-guard finding when
		// the same name@version reappears with different integrity.
		cache := gate.NewCache(gate.DefaultCacheRoot(), 7*24*time.Hour)
		results := gate.CachedRun(ctx, checkers, refs, cache)
		gate.SortByVerdict(results)

		// Render results — show problems first, then a summary.
		blocked, warned, unknown := 0, 0, 0
		for _, pc := range results {
			d := pc.Decision()
			if d == gate.VerdictApprove {
				continue
			}
			renderGateNode(os.Stderr, pc, gateExecExplain)
			switch d {
			case gate.VerdictBlock:
				blocked++
			case gate.VerdictWarn:
				warned++
			case gate.VerdictUnknown:
				unknown++
			}
		}
		fmt.Fprintf(os.Stderr, "\n[chdora] gate summary: %s\n", gate.Summarize(results))

		// Apply policy: only proceed if EVERY node Decides cleanly.
		// --dry-run surfaces the verdict but doesn't actually exec
		// — useful for "would this be blocked?" CI checks without
		// committing to the install.
		overall := overallVerdict(results, policy)
		if overall != gate.VerdictApprove {
			if gateExecDryRun {
				fmt.Fprintf(os.Stderr, "[chdora] --dry-run: gate would REFUSE (blocked=%d warned=%d unknown=%d)\n",
					blocked, warned, unknown)
			}
			return fmt.Errorf("install refused by gate: blocked=%d warned=%d unknown=%d (re-run with --lenient and/or --allow-offline to relax, or add per-package allowlist entries to chaindora.yml)",
				blocked, warned, unknown)
		}
		if gateExecDryRun {
			fmt.Fprintln(os.Stderr, "[chdora] --dry-run: gate approved (would exec real package manager)")
			return nil
		}
		fmt.Fprintf(os.Stderr, "[chdora] gate approved — exec %s %s\n", realBin, strings.Join(pmArgs, " "))
		return execReal(realBin, pmArgs)
	},
}

// renderGateNode prints one non-approve node's results to stderr in
// the same format `gate check` uses. Kept narrow on purpose: clean
// runs get no per-package output, just the summary line.
func renderGateNode(w *os.File, pc gate.PackageCheck, explain bool) {
	fmt.Fprintf(w, "\n%s  direct=%v\n", pc.Package, pc.Package.Direct)
	for _, r := range pc.Results {
		if r.Verdict == gate.VerdictApprove {
			continue
		}
		icon := "  ?   "
		switch r.Verdict {
		case gate.VerdictBlock:
			icon = "  !!  "
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
}

// overallVerdict reduces the per-package decisions to a single
// gate-wide verdict under the supplied policy. Block beats Unknown
// beats Warn beats Approve. We don't surface mixed states here —
// the caller already rendered per-node detail.
func overallVerdict(results []gate.PackageCheck, policy gate.Policy) gate.Verdict {
	worst := gate.VerdictApprove
	for _, pc := range results {
		allow, v := policy.Decide(pc)
		if allow {
			continue
		}
		switch v {
		case gate.VerdictBlock:
			return gate.VerdictBlock
		case gate.VerdictUnknown:
			if worst != gate.VerdictBlock {
				worst = gate.VerdictUnknown
			}
		case gate.VerdictWarn:
			if worst == gate.VerdictApprove {
				worst = gate.VerdictWarn
			}
		}
	}
	return worst
}

// isNPMInstallVerb covers the synonyms npm accepts.
func isNPMInstallVerb(v string) bool {
	switch v {
	case "install", "i", "add", "in", "ins", "isnt", "isntall":
		return true
	}
	return false
}

// isNPMUpdateVerb — `npm update` (alias `up`, `upgrade`) pulls newer
// versions of existing deps. Same threat surface as install for
// publisher-change / fresh-publish / new-CVE — gate it the same way.
func isNPMUpdateVerb(v string) bool {
	switch v {
	case "update", "up", "upgrade", "udpate":
		return true
	}
	return false
}

// isYarnInstallVerb — yarn classic uses `add`; Berry kept `add`.
// `yarn install` (with no args) installs from existing lockfile
// and isn't gated (vetted state already).
func isYarnInstallVerb(v string) bool {
	return v == "add"
}

// isYarnUpdateVerb — yarn classic: `yarn upgrade [pkg]` and
// `yarn upgrade-interactive`. Yarn Berry: `yarn up [pkg]`.
func isYarnUpdateVerb(v string) bool {
	switch v {
	case "upgrade", "upgrade-interactive", "up":
		return true
	}
	return false
}

// isPnpmInstallVerb — pnpm uses `add` for new packages and
// `install` for restoring from lockfile (not gated).
func isPnpmInstallVerb(v string) bool {
	return v == "add"
}

// isPnpmUpdateVerb — `pnpm update` (alias `up`, `upgrade`).
func isPnpmUpdateVerb(v string) bool {
	switch v {
	case "update", "up", "upgrade":
		return true
	}
	return false
}

// isPipInstallVerb covers pip / pip3. `pip install --upgrade` and
// `pip install -U` reuse this verb — the gate already sees the
// requested package(s) and resolves their latest version, so no
// separate update verb is needed.
func isPipInstallVerb(v string) bool {
	return v == "install"
}

// isCargoInstallVerb — `cargo add` adds to manifest;
// `cargo install` installs binaries globally (separate trust
// model, gate anyway).
func isCargoInstallVerb(v string) bool {
	return v == "add" || v == "install"
}

// isCargoUpdateVerb — `cargo update [pkg]` re-resolves Cargo.lock
// to newer compatible versions. Same threat surface as install for
// what's about to land in `target/`.
func isCargoUpdateVerb(v string) bool {
	return v == "update"
}

// isBundleInstallVerb — `bundle add` adds to Gemfile;
// `bundle install` restores from existing Gemfile.lock (not
// gated — already-vetted state).
func isBundleInstallVerb(v string) bool {
	return v == "add"
}

// isBundleUpdateVerb — `bundle update [gem]` re-resolves Gemfile.lock
// against newer compatible versions.
func isBundleUpdateVerb(v string) bool {
	return v == "update"
}

// isGemInstallVerb — `gem install` installs a gem.
func isGemInstallVerb(v string) bool {
	return v == "install"
}

// isGemUpdateVerb — `gem update [gem]` updates an installed gem.
func isGemUpdateVerb(v string) bool {
	return v == "update"
}

// isMavenInstallVerb — Maven doesn't have a clean equivalent;
// `mvn install` runs the full build cycle. We gate `mvn dependency:get`
// and `mvn dependency:tree` is read-only. For now, gate on
// `dependency:get` which is the explicit "fetch this dep" verb.
// Maven has no standalone upgrade verb — version bumps happen by
// editing pom.xml, then `dependency:get` runs through the gate.
func isMavenInstallVerb(v string) bool {
	return v == "dependency:get" || strings.HasPrefix(v, "dependency:") && strings.Contains(v, "get")
}

// isGoInstallVerb — `go get` adds modules to go.mod (or directly
// installs binaries). `go install` builds + installs binaries.
// `go run` doesn't pull new modules. We gate both. `go get -u`
// upgrades; same verb, just a flag, so already covered.
func isGoInstallVerb(v string) bool {
	return v == "get" || v == "install"
}

// isComposerInstallVerb — `composer require` is the package-add
// verb. `composer install` restores from existing composer.lock
// (already-vetted state → passthrough).
func isComposerInstallVerb(v string) bool { return v == "require" }

// isComposerUpdateVerb — `composer update [pkg]` re-resolves the
// lockfile against newer compatible versions.
func isComposerUpdateVerb(v string) bool { return v == "update" }

// isPoetryInstallVerb / UpdateVerb — Poetry's `add` adds to
// pyproject.toml + lockfile; `update` re-resolves to latest
// compatible. `install` restores from existing poetry.lock so
// passes through.
func isPoetryInstallVerb(v string) bool { return v == "add" }
func isPoetryUpdateVerb(v string) bool  { return v == "update" }

// isUVInstallVerb / UpdateVerb — uv's `add` adds to pyproject.toml.
// `uv lock --upgrade` re-resolves; `uv sync` restores from lockfile.
func isUVInstallVerb(v string) bool { return v == "add" }
func isUVUpdateVerb(v string) bool  { return v == "lock" }

// isGradleResolvingVerb covers the gradle tasks that trigger
// dependency resolution. Whitelist — anything not listed
// (`gradle wrapper`, `gradle init`, `gradle tasks`, `gradle clean`)
// passes through. The list errs on the side of "gate slightly more
// than necessary" because a missed verb that does pull deps
// silently bypasses the gate.
func isGradleResolvingVerb(v string) bool {
	switch v {
	case "build", "dependencies", "assemble", "test", "check",
		"compile", "compileJava", "compileKotlin",
		"compileTestJava", "compileTestKotlin",
		"run", "bootRun", "publish", "publishToMavenLocal",
		"installDist", "shadowJar":
		return true
	}
	return false
}

// isCocoaPodsResolvingVerb — `pod install` / `pod update` both
// trigger dep resolution. Other verbs (`pod init`, `pod search`,
// `pod outdated`) don't pull new content.
func isCocoaPodsResolvingVerb(v string) bool {
	return v == "install" || v == "update"
}

// isHexResolvingVerb — Mix dependency verbs that fetch from
// hex.pm. `mix deps.compile` also fetches if cache is cold.
func isHexResolvingVerb(v string) bool {
	switch v {
	case "deps.get", "deps.update", "deps.compile":
		return true
	}
	return false
}

// isBunInstallVerb — bun's add / install / i are all install
// verbs (i is alias). Lockfile-restore (`bun install` alone with
// existing bun.lockb) is handled by the no-args passthrough at
// the bottom of classifyGateArgs.
func isBunInstallVerb(v string) bool {
	switch v {
	case "add", "install", "i":
		return true
	}
	return false
}

// isCondaInstallVerb — conda / mamba / micromamba all expose
// `install` as the package-fetch verb. `update` and `upgrade`
// also pull new content.
func isCondaInstallVerb(v string) bool {
	switch v {
	case "install", "update", "upgrade":
		return true
	}
	return false
}

// isBrewInstallVerb — `brew install <formula>` is the gateable
// verb. `brew upgrade` and `brew reinstall` also fetch.
func isBrewInstallVerb(v string) bool {
	switch v {
	case "install", "upgrade", "reinstall":
		return true
	}
	return false
}

// isConanInstallVerb — Conan 2.x's `conan install <recipe>` is
// the gateable verb. We also gate `conan graph info` since users
// occasionally invoke it to surface vulnerabilities in their
// dep graph.
func isConanInstallVerb(v string) bool {
	switch v {
	case "install":
		return true
	}
	return false
}

// Round 1 verb classifiers.

func isPipenvInstallVerb(v string) bool { return v == "install" }
func isPDMInstallVerb(v string) bool    { return v == "add" }
func isDenoResolvingVerb(v string) bool {
	switch v {
	case "cache", "add", "install":
		return true
	}
	return false
}
func isStackResolvingVerb(v string) bool {
	switch v {
	case "build", "test", "ghci", "ls":
		return true
	}
	return false
}
func isCabalResolvingVerb(v string) bool {
	switch v {
	case "build", "install", "test", "run":
		return true
	}
	return false
}
func isSBTResolvingVerb(v string) bool {
	switch v {
	case "compile", "build", "test", "run", "package", "publishLocal", "dependencyTree":
		return true
	}
	return false
}
func isOpamInstallVerb(v string) bool { return v == "install" }
func isRebar3ResolvingVerb(v string) bool {
	switch v {
	case "compile", "build", "do", "deps", "release":
		return true
	}
	return false
}
func isPaketResolvingVerb(v string) bool {
	switch v {
	case "install", "update", "restore":
		return true
	}
	return false
}
func isVcpkgInstallVerb(v string) bool { return v == "install" }

// Round 2 verb classifiers.

// cpanm is unusual: most invocations are `cpanm Module::Name`
// with no explicit verb. We treat any non-flag first arg as an
// install request.
func isCpanmInstallArg(args []string) bool {
	if len(args) == 0 {
		return false
	}
	return !strings.HasPrefix(args[0], "-")
}
func isLuaRocksInstallVerb(v string) bool { return v == "install" }
func isCarthageResolvingVerb(v string) bool {
	switch v {
	case "update", "bootstrap", "build":
		return true
	}
	return false
}
func isElmInstallVerb(v string) bool { return v == "install" }
func isNimbleInstallVerb(v string) bool {
	switch v {
	case "install", "develop":
		return true
	}
	return false
}
func isShardsResolvingVerb(v string) bool {
	switch v {
	case "install", "update", "build":
		return true
	}
	return false
}
func isZigResolvingVerb(v string) bool {
	switch v {
	case "build", "test", "run":
		return true
	}
	return false
}

// isPMCwdOnly reports whether a PM's resolver operates against
// the user's project cwd rather than installArgs. These PMs have
// no "install <pkg>" CLI — devs edit the manifest by hand and run
// a resolver verb. The gate proceeds even when args contain only
// the verb (no positional packages to vet from the CLI).
func isPMCwdOnly(pm string) bool {
	switch pm {
	case "gradle", "pod", "swift", "mix":
		return true
	// Round 1 + 2 cwd-only additions.
	case "deno", "stack", "cabal", "sbt", "rebar3", "paket",
		"carthage", "shards", "zig", "julia", "R", "Rscript", "renv":
		return true
	}
	return false
}

// gateDecision describes what the dispatcher should do with a
// (package-manager, args) pair.
type gateDecision int

const (
	// gatePassthrough — not a gate-relevant verb, or install-with-no-args
	// (lockfile restore from already-vetted state).
	gatePassthrough gateDecision = iota
	// gateProceed — gate this command. installArgs (= args after the verb)
	// is forwarded to the resolver.
	gateProceed
	// gateRefuseUpdateAll — bare `npm update` / `pnpm update` / etc.
	// without explicit package names. The resolver needs project
	// context (user's actual package.json / Gemfile / Cargo.toml) to
	// know what "everything" expands to; we don't carry that context
	// into the temp-dir resolver yet, so we refuse with a clear error
	// rather than silently passing through.
	gateRefuseUpdateAll
)

// classifyGateArgs decides what the dispatcher should do for a
// package manager invocation. Centralizes the install-vs-update,
// lockfile-restore-vs-update-all, and gated-vs-passthrough logic
// so the switch in gateExecCmd stays uniform per package manager.
func classifyGateArgs(pm string, args []string) gateDecision {
	if len(args) == 0 {
		return gatePassthrough
	}
	verb := args[0]
	isInstall, isUpdate := false, false
	switch pm {
	case "npm":
		isInstall, isUpdate = isNPMInstallVerb(verb), isNPMUpdateVerb(verb)
	case "yarn":
		isInstall, isUpdate = isYarnInstallVerb(verb), isYarnUpdateVerb(verb)
	case "pnpm":
		isInstall, isUpdate = isPnpmInstallVerb(verb), isPnpmUpdateVerb(verb)
	case "pip", "pip3":
		isInstall = isPipInstallVerb(verb)
	case "cargo":
		isInstall, isUpdate = isCargoInstallVerb(verb), isCargoUpdateVerb(verb)
	case "bundle":
		isInstall, isUpdate = isBundleInstallVerb(verb), isBundleUpdateVerb(verb)
	case "gem":
		isInstall, isUpdate = isGemInstallVerb(verb), isGemUpdateVerb(verb)
	case "mvn":
		isInstall = isMavenInstallVerb(verb)
	case "go":
		isInstall = isGoInstallVerb(verb)
	case "dotnet":
		// dotnet's install verb is two tokens: `dotnet add package <id>`.
		// `dotnet add reference / project / ...` are different subcommands
		// (project-graph manipulation, no registry fetch) — passthrough.
		if len(args) >= 2 && args[0] == "add" && args[1] == "package" {
			isInstall = true
		}
	case "composer":
		isInstall, isUpdate = isComposerInstallVerb(verb), isComposerUpdateVerb(verb)
	case "poetry":
		isInstall, isUpdate = isPoetryInstallVerb(verb), isPoetryUpdateVerb(verb)
	case "uv":
		isInstall, isUpdate = isUVInstallVerb(verb), isUVUpdateVerb(verb)
	case "gradle":
		// Gradle has no install-args verb; we gate on tasks that
		// trigger resolution. classifyGateArgs returns gateProceed
		// for these even though args[0] is just the task name.
		if isGradleResolvingVerb(verb) {
			isInstall = true
		}
	case "pod":
		if isCocoaPodsResolvingVerb(verb) {
			isInstall = true
		}
	case "swift":
		// `swift package resolve` / `swift package update` — two-token
		// verbs. Other `swift package ...` subcommands (init, dump-package,
		// show-dependencies) don't fetch.
		if len(args) >= 2 && args[0] == "package" {
			switch args[1] {
			case "resolve", "update":
				isInstall = true
			}
		}
	case "dart", "flutter":
		// `dart pub add <pkg>` (with packages → install).
		// `dart pub get` / `upgrade` (cwd-based — also install).
		if len(args) >= 2 && args[0] == "pub" {
			switch args[1] {
			case "add", "get", "upgrade":
				isInstall = true
			}
		}
	case "mix":
		if isHexResolvingVerb(verb) {
			isInstall = true
		}
	case "bun":
		isInstall = isBunInstallVerb(verb)
	case "conda", "mamba", "micromamba":
		isInstall = isCondaInstallVerb(verb)
	case "brew":
		isInstall = isBrewInstallVerb(verb)
	case "conan":
		isInstall = isConanInstallVerb(verb)
	case "vcpkg":
		isInstall = isVcpkgInstallVerb(verb)
	case "pipenv":
		isInstall = isPipenvInstallVerb(verb)
	case "pdm":
		isInstall = isPDMInstallVerb(verb)
	case "deno":
		isInstall = isDenoResolvingVerb(verb)
	case "stack":
		if isStackResolvingVerb(verb) {
			isInstall = true
		}
	case "cabal":
		if isCabalResolvingVerb(verb) {
			isInstall = true
		}
	case "sbt":
		if isSBTResolvingVerb(verb) {
			isInstall = true
		}
	case "opam":
		isInstall = isOpamInstallVerb(verb)
	case "rebar3":
		if isRebar3ResolvingVerb(verb) {
			isInstall = true
		}
	case "paket":
		if isPaketResolvingVerb(verb) {
			isInstall = true
		}
	case "cpanm":
		isInstall = isCpanmInstallArg(args)
	case "luarocks":
		isInstall = isLuaRocksInstallVerb(verb)
	case "carthage":
		if isCarthageResolvingVerb(verb) {
			isInstall = true
		}
	case "elm":
		isInstall = isElmInstallVerb(verb)
	case "nimble":
		isInstall = isNimbleInstallVerb(verb)
	case "shards":
		if isShardsResolvingVerb(verb) {
			isInstall = true
		}
	case "zig":
		if isZigResolvingVerb(verb) {
			isInstall = true
		}
	case "julia", "R", "Rscript":
		// Pkg.jl and renv are REPL-driven; no clean install verb
		// to hook into at runtime. Gate every invocation that has
		// a project file in cwd — the cwd-only resolver will read
		// Manifest.toml / renv.lock and emit refs, otherwise no-op.
		isInstall = true
	default:
		return gatePassthrough
	}
	if !isInstall && !isUpdate {
		return gatePassthrough
	}
	if isInstall && len(args) == 1 && !isPMCwdOnly(pm) {
		// `npm install` alone — lockfile restore. Cwd-only PMs
		// (gradle/pod/swift/mix) intentionally have no positional
		// args; we still want to resolve their project state.
		return gatePassthrough
	}
	if isUpdate && len(args) == 1 {
		// `npm update` alone — every dep at once, no manifest context.
		return gateRefuseUpdateAll
	}
	return gateProceed
}

// findRealPackageManager looks up the binary on $PATH while skipping
// chdora's own shims — the critical recursion guard. Two layers of
// defense: (a) skip the canonical shim directory under whichever
// HOME we're running with; (b) content-sniff each candidate for the
// shim marker line, in case the user has copies elsewhere or HOME
// got reset between install and exec.
//
// Without this guard a shim-invocation of `chdora gate exec npm
// install ...` would find its own shim as "the real npm," exec
// itself, and infinite-loop until the OS killed the process tree.
func findRealPackageManager(name string) (string, error) {
	shimDir, _ := chaindoraShimDir()
	pathEnv := os.Getenv("PATH")
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			abs = dir
		}
		if shimDir != "" && abs == shimDir {
			continue
		}
		// Belt + suspenders: a directory ending in
		// `.chaindora/bin` is almost certainly our shim dir under
		// a different HOME (e.g. when chdora's HOME was reset
		// between `gate install` and `gate exec`).
		if filepath.Base(filepath.Dir(abs)) == ".chaindora" && filepath.Base(abs) == "bin" {
			continue
		}
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		if info.Mode()&0o111 == 0 {
			continue
		}
		// Final layer: sniff the file for the chdora-gate-shim
		// signature. If it IS a chdora shim, skip — recursion
		// would otherwise loop.
		if isChaindoraShim(candidate) {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("no real %s found on PATH (excluding chdora shim dirs)", name)
}

// isChaindoraShim peeks at the first ~256 bytes of a candidate
// binary and reports whether it carries the marker line we embed
// in shimContent. Reading 256 bytes off a small shell script is
// cheap; we never read non-text binaries far enough to matter.
func isChaindoraShim(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var buf [256]byte
	n, _ := f.Read(buf[:])
	return strings.Contains(string(buf[:n]), "chdora gate shim")
}

// chaindoraShimDir returns the canonical shim location used by the
// `chdora gate install` mechanism. Pulled into a helper so gate
// exec / install / disable agree on the location.
func chaindoraShimDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".chaindora", "bin"), nil
}

// asPMError unwraps an error chain looking for a *gate.PMError.
// Returns nil when err didn't originate from a non-zero PM exit
// (i.e. it's a chdora-internal failure — parse, network, etc.).
// The gate uses this to distinguish "the PM said no, just surface
// its diagnostics" from "chdora couldn't even ask".
func asPMError(err error) *gate.PMError {
	var pmErr *gate.PMError
	if errors.As(err, &pmErr) {
		return pmErr
	}
	return nil
}

// surfacePMError prints the package manager's captured output
// verbatim to stderr and exits with the PM's exit code. Used when
// the resolver step failed because the underlying PM rejected the
// command (typo'd package, 404, peer-dep conflict, malformed
// lockfile, ...). The install would have failed regardless of
// chdora, so the gate stays out of the way — no chdora prefix, no
// extra wrapping, no second invocation of the PM.
//
// Never returns.
func surfacePMError(pmErr *gate.PMError) {
	if len(pmErr.Output) > 0 {
		os.Stderr.Write(pmErr.Output)
		if pmErr.Output[len(pmErr.Output)-1] != '\n' {
			os.Stderr.WriteString("\n")
		}
	}
	code := pmErr.ExitCode
	if code == 0 {
		code = 1
	}
	os.Exit(code)
}

// isGatedPM reports whether the given package manager name is one
// chdora gate actively wraps (vs falls through). Single source of
// truth — `chdora gate status` reads from this so its display
// can't drift from the switch in gateExecCmd.
func isGatedPM(name string) bool {
	switch name {
	case "npm", "yarn", "pnpm", "pip", "pip3", "cargo", "bundle", "gem", "mvn", "go",
		"dotnet", "composer", "poetry", "uv", "gradle",
		"pod", "swift", "dart", "flutter", "mix",
		"bun", "conda", "mamba", "micromamba", "brew", "conan",
		"pipenv", "pdm", "deno", "stack", "cabal", "sbt", "opam",
		"rebar3", "paket", "vcpkg",
		"cpanm", "luarocks", "carthage", "elm", "nimble", "shards", "zig",
		"julia", "R", "Rscript":
		return true
	}
	return false
}

// passThroughToReal is the fallback path for package managers the
// gate doesn't (yet) gate — pip, yarn, pnpm. We just find the real
// binary on PATH (skipping our shim dir) and exec it. No gating, no
// noise; the user shouldn't notice chdora is in the path.
func passThroughToReal(name string, args []string) error {
	real, err := findRealPackageManager(name)
	if err != nil {
		return err
	}
	return execReal(real, args)
}

// execReal hands control off to the real package manager — fully
// transparent, the user sees identical output to what they'd see
// without chdora in the path.
func execReal(bin string, args []string) error {
	// We use exec.Command + Run rather than syscall.Exec so the
	// gate's "approved — exec'ing" line stays visible; with a true
	// exec, our stderr line gets clobbered if npm itself fails fast.
	cmd := exec.Command(bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// Propagate the real process's exit code.
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				os.Exit(ws.ExitStatus())
			}
			os.Exit(1)
		}
		return err
	}
	return nil
}

// splitGateExecArgs partitions raw cobra args into (gate flags,
// package-manager + its args). The first non-flag arg is the
// package-manager name; everything after it is forwarded as-is.
//
// Supports the standard "--flag value" and "--flag=value" forms.
// Doesn't support short flags (-l) for chdora's flags — the four
// users would actually type would clash with npm's short flags (npm
// -g, npm -D, ...) and the ambiguity isn't worth it.
func splitGateExecArgs(args []string) (chdora []string, pm []string, err error) {
	i := 0
	for i < len(args) {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			pm = args[i:]
			return chdora, pm, nil
		}
		// Known boolean chdora flags consume no value.
		switch a {
		case "--lenient", "--allow-offline", "--skip-osv", "--skip-static", "--explain", "--dry-run":
			chdora = append(chdora, a)
			i++
			continue
		}
		// `--cooldown <value>` takes the next arg as the value.
		if a == "--cooldown" {
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("--cooldown requires a value")
			}
			chdora = append(chdora, a, args[i+1])
			i += 2
			continue
		}
		// `--flag=value` form for cooldown.
		if strings.HasPrefix(a, "--cooldown=") {
			chdora = append(chdora, a)
			i++
			continue
		}
		// Unknown leading flag — assume it belongs to the
		// package manager. The first non-flag positional will
		// disambiguate; up to then we just collect.
		pm = args[i:]
		return chdora, pm, nil
	}
	return chdora, pm, nil
}

// applyGateExecFlags interprets the chdora-side flags into the
// package-level vars used during the run. Same defaults cobra
// would have wired up; just doing it by hand because we disabled
// cobra parsing.
func applyGateExecFlags(flags []string) error {
	gateExecCooldown = 0
	gateExecLenient = false
	gateExecOffline = false
	gateExecSkipOSV = false
	gateExecSkipStatic = false
	gateExecExplain = false
	gateExecDryRun = false
	for i := 0; i < len(flags); i++ {
		switch flags[i] {
		case "--lenient":
			gateExecLenient = true
		case "--allow-offline":
			gateExecOffline = true
		case "--skip-osv":
			gateExecSkipOSV = true
		case "--skip-static":
			gateExecSkipStatic = true
		case "--explain":
			gateExecExplain = true
		case "--dry-run":
			gateExecDryRun = true
		case "--cooldown":
			if i+1 >= len(flags) {
				return fmt.Errorf("--cooldown needs a value")
			}
			d, err := time.ParseDuration(flags[i+1])
			if err != nil {
				return fmt.Errorf("--cooldown %q: %w", flags[i+1], err)
			}
			gateExecCooldown = d
			i++
		default:
			if strings.HasPrefix(flags[i], "--cooldown=") {
				v := strings.TrimPrefix(flags[i], "--cooldown=")
				d, err := time.ParseDuration(v)
				if err != nil {
					return fmt.Errorf("--cooldown %q: %w", v, err)
				}
				gateExecCooldown = d
			}
		}
	}
	return nil
}

func init() {
	gateCmd.AddCommand(gateExecCmd)
}
