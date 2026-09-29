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
// Supported managers are listed in pmClassifiers. Coverage is command-specific;
// restore/build commands and several bare install forms pass through.

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

Supported managers: npm, yarn, pnpm, bun, deno, pip, pip3, poetry,
uv, pipenv, pdm, dotnet, paket, go, cargo. Other managers are refused.

Coverage is command-specific. Bare npm install, npm ci, uv pip install,
restore/build commands and unrecognized verbs can pass through ungated.
Resolution is not sandboxed and the later install is not frozen to the
checked artifacts. See README.md#supported-scope and docs/threat-model.md.

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
		if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
			return cmd.Help()
		}
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

		if !isGatedPM(pm) {
			return fmt.Errorf("unsupported package manager %q: supported ecosystems are npm, PyPI, .NET, Go, and Rust", pm)
		}
		realBin, err := findRealPackageManager(pm)
		if err != nil {
			return err
		}
		// Deno and Paket resolve project state from the current directory.
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
		case "go":
			resolve = gate.ResolveGoModTree
		case "dotnet":
			resolve = gate.ResolveNuGetTree
		case "poetry":
			resolve = gate.ResolvePoetryTree
		case "uv":
			resolve = gate.ResolveUVTree
		case "bun":
			resolve = gate.ResolveBunTree
		case "pipenv":
			resolve = gate.ResolvePipenvTree
		case "pdm":
			resolve = gate.ResolvePDMTree
		case "deno":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolveDenoTree(ctx, bin, cwd)
			}
		case "paket":
			resolve = func(ctx context.Context, bin string, _ []string) ([]gate.PackageRef, error) {
				return gate.ResolvePaketTree(ctx, bin, cwd)
			}
		default:
			return fmt.Errorf("unsupported package manager %q: supported ecosystems are npm, PyPI, .NET, Go, and Rust", pm)
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
					return surfacePMError(pmErr)
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
			// Deno and Paket read project state from cwd. Skip the
			// no-args passthrough used by the other resolvers.
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
					return surfacePMError(pmErr)
				}
				return fmt.Errorf("resolve tree: %w", err)
			}
		}
		fmt.Fprintf(os.Stderr, "[chdora] tree resolved: %d unique (name, version) tuple(s)\n", len(refs))

		// Gate every node. CachedRun reads from ~/.chaindora/gate-cache/
		// as integrity history, reruns every current checker, and
		// inserts a republish-guard finding when
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
// and isn't currently gated.
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

// isGoInstallVerb — `go get` adds modules to go.mod (or directly
// installs binaries). `go install` builds + installs binaries.
// `go run` can fetch modules but is not currently gated. `go get -u`
// upgrades; same verb, just a flag, so already covered.
func isGoInstallVerb(v string) bool {
	return v == "get" || v == "install"
}

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

func isPipenvInstallVerb(v string) bool { return v == "install" }
func isPDMInstallVerb(v string) bool    { return v == "add" }
func isDenoResolvingVerb(v string) bool {
	switch v {
	case "cache", "add", "install":
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

// isPMCwdOnly reports whether a PM's resolver operates against
// the user's project cwd rather than installArgs. These PMs have
// no "install <pkg>" CLI — devs edit the manifest by hand and run
// a resolver verb. The gate proceeds even when args contain only
// the verb (no positional packages to vet from the CLI).
func isPMCwdOnly(pm string) bool { return pm == "deno" || pm == "paket" }

// gateDecision describes what the dispatcher should do with a
// (package-manager, args) pair.
type gateDecision int

const (
	// gatePassthrough — not a gate-relevant verb, or install-with-no-args
	// (the current implementation does not inspect those restore paths).
	gatePassthrough gateDecision = iota
	// gateProceed — gate this command. installArgs (= args after the verb)
	// is forwarded to the resolver.
	gateProceed
	// gateRefuseUpdateAll — bare `npm update` / `pnpm update` / etc.
	// without explicit package names. The resolver needs project
	// context (user's actual package.json / Cargo.toml) to
	// know what "everything" expands to; we don't carry that context
	// into the temp-dir resolver yet, so we refuse with a clear error
	// rather than silently passing through.
	gateRefuseUpdateAll
)

// pmClassifier is the per-PM logic the dispatcher needs. Each PM
// registers one entry in the pmClassifiers table below; the dispatcher
// becomes a thin wrapper around the table. Replaces the 153-line
// switch that grew per-ecosystem .
//
// install / update each receive the FULL args slice (not just verb)
// because some PMs (dotnet) use multi-token verbs that
// need to peek at args[1]. Returning bool lets the predicate use any
// shape it likes (single-verb switch, regex, prefix scan).
type pmClassifier struct {
	// install is true when args describes an install request that
	// fetches new packages (or, for cwd-only PMs, runs a resolving
	// task against the project's manifest). nil for PMs that have
	// no install path.
	install func(args []string) bool
	// update is true when args describes an update / upgrade
	// request. Set only for PMs that distinguish update from
	// install (npm/yarn/pnpm/cargo/poetry/uv).
	// nil for PMs where update is folded into install (pip --upgrade,
	// pip3 --upgrade).
	update func(args []string) bool
}

// pmClassifiers is the verb table. Each row replaces a case of the
// former giant switch. Adding a new PM means appending a row plus
// updating shimManagers.
var pmClassifiers = map[string]pmClassifier{
	"npm":    {install: oneArgVerbFn(isNPMInstallVerb), update: oneArgVerbFn(isNPMUpdateVerb)},
	"yarn":   {install: oneArgVerbFn(isYarnInstallVerb), update: oneArgVerbFn(isYarnUpdateVerb)},
	"pnpm":   {install: oneArgVerbFn(isPnpmInstallVerb), update: oneArgVerbFn(isPnpmUpdateVerb)},
	"pip":    {install: oneArgVerbFn(isPipInstallVerb)},
	"pip3":   {install: oneArgVerbFn(isPipInstallVerb)},
	"cargo":  {install: oneArgVerbFn(isCargoInstallVerb), update: oneArgVerbFn(isCargoUpdateVerb)},
	"go":     {install: oneArgVerbFn(isGoInstallVerb)},
	"poetry": {install: oneArgVerbFn(isPoetryInstallVerb), update: oneArgVerbFn(isPoetryUpdateVerb)},
	"uv":     {install: oneArgVerbFn(isUVInstallVerb), update: oneArgVerbFn(isUVUpdateVerb)},
	"bun":    {install: oneArgVerbFn(isBunInstallVerb)},
	"pipenv": {install: oneArgVerbFn(isPipenvInstallVerb)},
	"pdm":    {install: oneArgVerbFn(isPDMInstallVerb)},
	"deno":   {install: oneArgVerbFn(isDenoResolvingVerb)},
	"paket":  {install: oneArgVerbFn(isPaketResolvingVerb)},

	// Multi-token verbs — encapsulated in install so the dispatcher
	// stays uniform. Each predicate inspects args[0..N].
	"dotnet": {install: isDotnetAddPackage},
}

// oneArgVerbFn adapts an existing `is<X>Verb(string) bool` predicate
// (operating on args[0]) into the args-slice shape pmClassifier expects.
// Most PMs use this; multi-token PMs (dotnet) write their own.
func oneArgVerbFn(p func(string) bool) func([]string) bool {
	return func(args []string) bool {
		if len(args) == 0 {
			return false
		}
		return p(args[0])
	}
}

// isDotnetAddPackage matches `dotnet add package <id>`. Other forms of
// `dotnet add ...` (reference, project) manipulate the project graph
// without fetching from a registry — passthrough.
func isDotnetAddPackage(args []string) bool {
	return len(args) >= 2 && args[0] == "add" && args[1] == "package"
}

// classifyGateArgs decides what the dispatcher should do for a
// package manager invocation. Centralizes the install-vs-update,
// lockfile-restore-vs-update-all, and gated-vs-passthrough logic
// so the switch in gateExecCmd stays uniform per package manager.
//
// refactored from a 153-line switch to a verb table
// (pmClassifiers). Each PM is one row in the table; the dispatcher is
// a uniform shape that reads from the table. Adding a new PM is now
// "append a row" instead of "add a case." Behavior is preserved
// exactly — see TestClassifyGateArgs in gate_exec_test.go for the
// characterization-test sweep that gated the refactor.
func classifyGateArgs(pm string, args []string) gateDecision {
	c, ok := pmClassifiers[pm]
	if !ok {
		return gatePassthrough
	}
	if len(args) == 0 {
		return gatePassthrough
	}
	isInstall := c.install != nil && c.install(args)
	isUpdate := c.update != nil && c.update(args)
	if !isInstall && !isUpdate {
		return gatePassthrough
	}
	if isInstall && len(args) == 1 && !isPMCwdOnly(pm) {
		// `npm install` alone — lockfile restore. Cwd-only PMs
		// (deno/paket) intentionally have no positional
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
// verbatim to stderr and returns an *ExitError carrying the PM's
// original exit code. Used when the resolver step failed because the
// underlying PM rejected the command (typo'd package, 404, peer-dep
// conflict, malformed lockfile, ...). The install would have failed
// regardless of chdora, so the gate stays out of the way — no chdora
// prefix, no extra wrapping, no second invocation of the PM.
//
// returns an error instead of calling os.Exit directly, so
// the RunE handler stays the single source of exit semantics and the
// function becomes testable. Callers must `return surfacePMError(pmErr)`
// instead of relying on a "never returns" contract.
func surfacePMError(pmErr *gate.PMError) error {
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
	return SilentExit(code)
}

// isGatedPM reports whether the given package manager name is one
// chdora gate actively wraps (vs falls through). Single source of
// truth — `chdora gate status` reads from this so its display
// can't drift from the switch in gateExecCmd.
func isGatedPM(pm string) bool {
	_, ok := pmClassifiers[pm]
	return ok
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
			// Propagate the real process's exit code via the
			// typed ExitError so root.Execute does the os.Exit
			// — not us. .
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return SilentExit(ws.ExitStatus())
			}
			return SilentExit(1)
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
