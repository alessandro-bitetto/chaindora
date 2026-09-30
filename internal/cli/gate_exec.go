package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/alessandro-bitetto/chaindora/internal/artifacts"
	"github.com/alessandro-bitetto/chaindora/internal/gate"
)

// gate exec accepts only frozen npm restores. All other acquisition and
// execution routes refuse before looking up or invoking a package manager.
// Exact help/version requests are the only uninspected handoff.

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
	Short: "Install a frozen npm lockfile from verified artifacts, with scripts disabled",
	Long: `Checks every package in an existing npm v2/v3 lockfile, downloads and verifies
its artifacts, and installs those same bytes offline in a private staging directory.
Lifecycle scripts are disabled. The current node_modules is replaced only after
staged file contents and unchanged project inputs are verified.

Use: chdora gate exec npm ci
     chdora gate exec --dry-run npm install

Only public-registry npm restores on macOS/Linux are currently covered. Package additions,
updates, workspaces, custom registries and unsupported flags are refused.
Other managers are refused for install/build/run operations until a frozen
adapter exists. Exact --version/-v/--help/-h requests pass through.
Gate flags precede the manager name; manager arguments follow it.
The gate is not an operating-system sandbox. Package manager binaries and the
local operating system remain trusted.`,
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
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}

		cfg, err := gate.LoadConfig(cwd)
		if err != nil {
			return fmt.Errorf("gate configuration: %w", err)
		}

		decision := classifyGateArgs(pm, pmArgs)
		if decision == gateRefuse {
			return fmt.Errorf("install refused: %s command is not covered by a frozen transaction; use npm ci with a reviewed public-registry lockfile, or scan existing dependencies", pm)
		}
		if decision == gateProceed && runtime.GOOS == "windows" {
			return fmt.Errorf("frozen npm installs require macOS or Linux; Windows scanning remains available")
		}

		realBin, err := findRealPackageManager(pm)
		if err != nil {
			return err
		}
		if decision == gatePassthrough {
			return execReal(realBin, pmArgs)
		}

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

		fmt.Fprintln(os.Stderr, "[chdora] verifying artifacts from the frozen npm lockfile (lifecycle scripts disabled)")
		tx, err := gate.PrepareNPMTransaction(ctx, realBin, cwd, pmArgs, nil, artifacts.DefaultCacheRoot())
		if err != nil {
			return fmt.Errorf("prepare frozen install: %w", err)
		}
		defer func() {
			if err := tx.Close(); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "[chdora] install cleanup/recovery pending: %v\n", err)
			}
		}()
		refs := tx.Refs

		fmt.Fprintf(os.Stderr, "[chdora] tree resolved: %d unique (name, version) tuple(s)\n", len(refs))
		if len(refs) == 0 {
			return fmt.Errorf("install refused: resolution produced no inspectable packages; an empty dependency tree cannot authorize installation")
		}

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
			fmt.Fprintln(os.Stderr, "[chdora] --dry-run: frozen artifacts approved; installation not executed")
			return nil
		}
		fmt.Fprintln(os.Stderr, "[chdora] gate approved — installing verified artifacts offline with scripts disabled")
		if err := tx.Install(ctx); err != nil {
			if pmErr := asPMError(err); pmErr != nil {
				return surfacePMError(pmErr)
			}
			return err
		}
		return nil
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
	if len(results) == 0 {
		return gate.VerdictUnknown
	}
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

// Wrapper names remain recognized so unsupported installs are refused explicitly.
var pmClassifiers = map[string]struct{}{
	"npm": {}, "yarn": {}, "pnpm": {}, "bun": {}, "deno": {}, "pip": {}, "pip3": {},
	"poetry": {}, "uv": {}, "pipenv": {}, "pdm": {}, "dotnet": {}, "paket": {}, "go": {}, "cargo": {},
}

type gateDecision int

const (
	gatePassthrough gateDecision = iota
	gateProceed
	gateRefuse
)

// Only exact read-only version/help requests bypass the transaction boundary.
// Unknown verbs, flags before verbs and restore/build/run paths refuse rather
// than relying on a blacklist of commands that might fetch or execute packages.
func classifyGateArgs(pm string, args []string) gateDecision {
	if !isGatedPM(pm) {
		return gateRefuse
	}
	if len(args) == 1 {
		switch args[0] {
		case "--version", "-v", "--help", "-h":
			return gatePassthrough
		}
	}
	if pm == "npm" && gate.ValidateNPMRestoreArgs(args) == nil {
		return gateProceed
	}
	return gateRefuse
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
		candidate := filepath.Join(abs, name)
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
	// Passthrough commands reach this function before resolution. Dry-run
	// must prevent those handoffs too; it must never execute an install.
	if gateExecDryRun {
		fmt.Fprintf(os.Stderr, "[chdora] --dry-run: would pass through %s %s (not inspected); command not executed\n", bin, strings.Join(args, " "))
		return nil
	}
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
