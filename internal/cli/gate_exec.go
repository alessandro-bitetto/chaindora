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
		var installArgs []string
		var resolve func(context.Context, string, []string) ([]gate.PackageRef, error)
		switch pm {
		case "npm":
			if len(pmArgs) == 0 || !isNPMInstallVerb(pmArgs[0]) || len(pmArgs) == 1 {
				return execReal(realBin, pmArgs)
			}
			installArgs = pmArgs[1:]
			resolve = gate.ResolveNPMTree
		case "yarn":
			if len(pmArgs) == 0 || !isYarnInstallVerb(pmArgs[0]) || len(pmArgs) == 1 {
				return execReal(realBin, pmArgs)
			}
			installArgs = pmArgs[1:]
			resolve = gate.ResolveYarnTree
		case "pnpm":
			if len(pmArgs) == 0 || !isPnpmInstallVerb(pmArgs[0]) || len(pmArgs) == 1 {
				return execReal(realBin, pmArgs)
			}
			installArgs = pmArgs[1:]
			resolve = gate.ResolvePnpmTree
		default:
			return passThroughToReal(pm, pmArgs)
		}
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

		cwd, _ := os.Getwd()
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

		fmt.Fprintf(os.Stderr, "[chdora] resolving install tree (%s) for: %s\n", pm, strings.Join(pmArgs, " "))
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		refs, err := resolve(ctx, realBin, installArgs)
		if err != nil {
			return fmt.Errorf("resolve tree: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[chdora] tree resolved: %d unique (name, version) tuple(s)\n", len(refs))

		// Gate every node.
		results := gate.Run(ctx, checkers, refs)
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

// isYarnInstallVerb — yarn classic uses `add`; Berry kept `add`.
// `yarn install` (with no args) installs from existing lockfile
// and isn't gated (vetted state already).
func isYarnInstallVerb(v string) bool {
	return v == "add"
}

// isPnpmInstallVerb — pnpm uses `add` for new packages and
// `install` for restoring from lockfile (not gated).
func isPnpmInstallVerb(v string) bool {
	return v == "add"
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
