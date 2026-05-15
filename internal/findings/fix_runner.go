package findings

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// RunOptions configures how RunFixes treats a slice of plans.
type RunOptions struct {
	// PlanOnly prints each plan and returns without prompting or executing.
	PlanOnly bool

	// AutoYes applies every plan whose Category is in AllowedCategories
	// without prompting. The runner still skips Manual / Unsafe plans
	// (those never execute).
	AutoYes bool

	// AllowedCategories filters which categories are eligible for
	// auto-apply under AutoYes. Defaults to {FixSafe}.
	AllowedCategories []FixCategory

	// Stdin lets tests inject input. Falls back to os.Stdin.
	Stdin io.Reader

	// Output is where the runner writes its diagnostic messages and the
	// stdout/stderr of executed commands. Falls back to os.Stderr.
	Output io.Writer
}

// RunFixes evaluates plans, optionally prompts, and executes Commands.
// Returns counts (applied / no-op / skipped) plus the first execution error.
// "applied" counts commands that completed cleanly AND visibly changed state
// (e.g. pip's "Successfully installed X-V" line). "no-op" counts commands
// that completed cleanly but didn't change anything — typically a pip
// upgrade hitting a Python-version cap or PATH issue. Those are surfaced
// inline as warnings so the user knows a follow-up step is needed.
func RunFixes(ctx context.Context, plans []FixPlan, opts RunOptions) (applied, skipped int, err error) {
	out := opts.Output
	if out == nil {
		out = os.Stderr
	}
	in := bufio.NewReader(stdinOr(opts.Stdin))
	allowed := opts.AllowedCategories
	if len(allowed) == 0 {
		allowed = []FixCategory{FixSafe}
	}

	plans = DedupePlans(plans)
	if len(plans) == 0 {
		fmt.Fprintln(out, "no fixable findings")
		return 0, 0, nil
	}
	fmt.Fprintf(out, "\n=== %d fix plan(s) ===\n", len(plans))

	autoApplyRest := false
	noOp := 0
	// Probe the active Python interpreter once per RunFixes call. If any
	// pip plan hits a no-op, we'll append an EOL heads-up so the user
	// knows whether their interpreter is the cause.
	pythonNote := pythonEOLNote(ctx)

	for i, p := range plans {
		printPlan(out, i+1, len(plans), p)

		if opts.PlanOnly {
			continue
		}
		if !p.Executable() {
			skipped++
			continue
		}

		shouldApply := false
		switch {
		case autoApplyRest:
			shouldApply = true
		case opts.AutoYes && categoryAllowed(p.Category, allowed):
			shouldApply = true
		default:
			choice := promptFix(out, in)
			switch choice {
			case "a":
				shouldApply = true
			case "A":
				shouldApply = true
				autoApplyRest = true
			case "q":
				fmt.Fprintln(out, "aborted by user")
				return applied, skipped, nil
			default:
				skipped++
				continue
			}
		}

		if !shouldApply {
			skipped++
			continue
		}
		fmt.Fprintf(out, "  applying: %s\n", p.Command)
		captured, execErr := executeCommand(ctx, p.Command, out)
		if execErr != nil {
			fmt.Fprintf(out, "  FAILED: %v\n", execErr)
			skipped++
			if err == nil {
				err = execErr
			}
			continue
		}
		if isPipNoOp(p.Command, captured) {
			noOp++
			fmt.Fprintln(out, "  WARNING: command ran cleanly but did NOT change the installed version.")
			fmt.Fprintln(out, "           Likely cause: the version that fixes this CVE requires a newer")
			fmt.Fprintln(out, "           Python interpreter, or your $PATH is masking the upgraded binary.")
			if pythonNote != "" {
				fmt.Fprintf(out, "           %s\n", pythonNote)
			}
			continue
		}
		applied++
		fmt.Fprintln(out, "  ok")
	}

	fmt.Fprintf(out, "\nfixes: applied=%d, no-op=%d, skipped=%d\n", applied, noOp, skipped)
	return applied, skipped, err
}

func printPlan(w io.Writer, n, total int, p FixPlan) {
	fmt.Fprintf(w, "\nFix %d/%d  [%s] [%s] %s\n", n, total, p.Severity, p.Category, p.VulnID)
	fmt.Fprintf(w, "  %s\n", p.Description)
	if p.Command != "" {
		fmt.Fprintf(w, "  command: %s\n", p.Command)
	}
	// Surface the full covered set when more than one finding rolled up
	// into this plan, so the user sees that "one upgrade addresses N CVEs"
	// instead of just the highest-severity headline.
	if extras := otherVulnIDs(p); len(extras) > 0 {
		fmt.Fprintf(w, "  also addresses: %s\n", strings.Join(extras, ", "))
	}
	for _, s := range p.ManualSteps {
		fmt.Fprintf(w, "  step: %s\n", s)
	}
}

// otherVulnIDs returns CoveredVulnIDs minus the headline VulnID, in stable
// order. Returns nil when there's nothing extra to surface.
func otherVulnIDs(p FixPlan) []string {
	if len(p.CoveredVulnIDs) <= 1 {
		return nil
	}
	out := make([]string, 0, len(p.CoveredVulnIDs)-1)
	for _, id := range p.CoveredVulnIDs {
		if id != p.VulnID {
			out = append(out, id)
		}
	}
	return out
}

func categoryAllowed(c FixCategory, allowed []FixCategory) bool {
	for _, a := range allowed {
		if a == c {
			return true
		}
	}
	return false
}

func promptFix(w io.Writer, r *bufio.Reader) string {
	fmt.Fprint(w, "  [a]pply  [s]kip  [A]pply all remaining  [q]uit > ")
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "q"
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "s"
	}
	// Preserve case for the capital-A "apply all" affordance
	return string(line[0])
}

// executeCommand runs the plan's shell command via `sh -c` on Unix. Windows
// is currently a no-op: --fix prints the command and skips execution, with
// guidance to run it manually in PowerShell or cmd. Returns the captured
// stdout+stderr alongside any execution error so the caller can post-check
// for "command succeeded but didn't change anything" cases.
func executeCommand(ctx context.Context, cmd string, out io.Writer) (string, error) {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(out, "  (Windows: automated execution not yet supported — run the command manually)")
		return "", nil
	}
	var buf bytes.Buffer
	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	c.Stdout = io.MultiWriter(out, &buf)
	c.Stderr = io.MultiWriter(out, &buf)
	err := c.Run()
	return buf.String(), err
}

// isPipNoOp reports whether a pip-install command appears to have completed
// without actually changing anything. pip's wire-protocol marker for a real
// install is the "Successfully installed <pkg>-<version>" line; its absence
// after a clean exit means either everything was already at the requested
// version OR (the common case for these CVEs) the resolver couldn't find a
// newer version that supports the active Python interpreter.
func isPipNoOp(cmd, output string) bool {
	if !looksLikePipInstall(cmd) {
		return false
	}
	if strings.Contains(output, "Successfully installed") {
		return false
	}
	// "Requirement already satisfied" appears even on successful upgrades
	// (the system-site copy is reported as satisfied before the new copy
	// lands in user-site), so it isn't a reliable noop signal on its own.
	// The reliable signal is the absence of "Successfully installed".
	return true
}

var pipInstallRe = regexp.MustCompile(`\b(pip\s+install|python\d*\s+-m\s+pip\s+install)\b`)

func looksLikePipInstall(cmd string) bool {
	return pipInstallRe.MatchString(cmd)
}

// pythonEOL holds Python end-of-life dates. Source:
// https://devguide.python.org/versions/  (review every 6 months; new minor
// releases push the table forward by one row).
var pythonEOL = map[string]time.Time{
	"3.7":  time.Date(2023, 6, 27, 0, 0, 0, 0, time.UTC),
	"3.8":  time.Date(2024, 10, 7, 0, 0, 0, 0, time.UTC),
	"3.9":  time.Date(2025, 10, 31, 0, 0, 0, 0, time.UTC),
	"3.10": time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC),
	"3.11": time.Date(2027, 10, 31, 0, 0, 0, 0, time.UTC),
	"3.12": time.Date(2028, 10, 31, 0, 0, 0, 0, time.UTC),
	"3.13": time.Date(2029, 10, 31, 0, 0, 0, 0, time.UTC),
}

// pythonEOLNote returns a one-line warning when the active `python3` is past
// its EOL date, or "" if `python3` isn't on PATH / the version isn't known.
func pythonEOLNote(ctx context.Context) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	c := exec.CommandContext(ctx, "python3", "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
	out, err := c.Output()
	if err != nil {
		return ""
	}
	ver := strings.TrimSpace(string(out))
	eol, ok := pythonEOL[ver]
	if !ok {
		return ""
	}
	if !time.Now().After(eol) {
		return ""
	}
	return fmt.Sprintf("Your `python3` is %s — EOL since %s. The pip/setuptools/wheel maintainers "+
		"have dropped support for it, so newer CVE-fixed versions won't install. "+
		"Install a current Python (e.g. `brew install python@3.12`) and re-run.",
		ver, eol.Format("2006-01-02"))
}

func stdinOr(r io.Reader) io.Reader {
	if r != nil {
		return r
	}
	return os.Stdin
}

// dedupePlansByCommand collapses identical executable Commands so we don't
// re-run `python3 -m pip install --upgrade pip` once per pip CVE. Manual /
// command-less plans pass through untouched — each finding keeps its own
// remediation steps. Highest-severity finding wins for the kept entry's
// headline metadata; CoveredVulnIDs accumulates every collapsed VulnID so
// the user can see the full set this one command addresses.
func dedupePlansByCommand(plans []FixPlan) []FixPlan {
	seen := map[string]int{}
	covered := map[string]map[string]struct{}{} // command → set of vuln ids
	out := make([]FixPlan, 0, len(plans))
	for _, p := range plans {
		if p.Command == "" {
			out = append(out, p)
			continue
		}
		if idx, ok := seen[p.Command]; ok {
			if severityRank(p.Severity) > severityRank(out[idx].Severity) {
				out[idx].Severity = p.Severity
				out[idx].VulnID = p.VulnID
				out[idx].Description = p.Description
			}
			if p.VulnID != "" {
				covered[p.Command][p.VulnID] = struct{}{}
			}
			// Preserve CoveredVulnIDs already set upstream — e.g.
			// dedupePlansByPackage emits plans whose CoveredVulnIDs
			// is already the union across N CVEs; we must NOT drop
			// those by overwriting here.
			for _, id := range p.CoveredVulnIDs {
				if id != "" {
					covered[p.Command][id] = struct{}{}
				}
			}
			continue
		}
		seen[p.Command] = len(out)
		covered[p.Command] = map[string]struct{}{}
		if p.VulnID != "" {
			covered[p.Command][p.VulnID] = struct{}{}
		}
		// Seed the per-command covered set from any pre-existing
		// CoveredVulnIDs so dedupePlansByPackage's output is preserved.
		for _, id := range p.CoveredVulnIDs {
			if id != "" {
				covered[p.Command][id] = struct{}{}
			}
		}
		out = append(out, p)
	}
	// Flatten the per-plan covered set into a stable slice. Sorted so the
	// output is deterministic across runs.
	for i := range out {
		set := covered[out[i].Command]
		if len(set) == 0 {
			continue
		}
		ids := make([]string, 0, len(set))
		for id := range set {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out[i].CoveredVulnIDs = ids
	}
	return out
}

// DedupePlans is the public composition of the two dedup passes used
// to fold per-CVE plans into the minimum executable set. Package-level
// dedup runs first (collapses N CVEs against one package into a single
// max-pinned plan); command-level dedup runs second (collapses any
// remaining commands that happen to be byte-identical). Both passes
// are idempotent — repeated application returns the same slice.
//
// Exported because the CLI calls it before saving plans (v0.8.0
// --save-plan) so the saved artifact matches what will execute.
func DedupePlans(plans []FixPlan) []FixPlan {
	plans = dedupePlansByPackage(plans)
	plans = dedupePlansByCommand(plans)
	return plans
}

// dedupePlansByPackage (v0.8.1) collapses multiple CVE plans against
// the same (ProjectDir, PackageName) into a single plan pinned to the
// MAX required version across the group. Without this, a package with
// 5 CVEs produces 5 sequential `npm install pkg@^X` commands at
// different pins; the later ones either no-op or, worse, downgrade
// the install the earlier one performed.
//
// Plans missing dedup keys (ProjectDir/PackageName/RequiredVersion all
// blank) pass through untouched — incident-pack fixes, global-package
// fixes, and Manual entries don't participate.
//
// The winning plan keeps its dedup keys (so dedupePlansByCommand,
// which runs after this, treats it as the source-of-truth command).
// Severity follows the highest-severity finding in the group;
// CoveredVulnIDs accumulates every collapsed VulnID, sorted, for the
// "also addresses: …" line in printPlan.
func dedupePlansByPackage(plans []FixPlan) []FixPlan {
	type key struct{ dir, pkg string }
	groups := map[key][]int{}
	for i, p := range plans {
		if p.PackageName == "" || p.RequiredVersion == "" {
			continue
		}
		k := key{p.ProjectDir, p.PackageName}
		groups[k] = append(groups[k], i)
	}
	out := make([]FixPlan, 0, len(plans))
	emitted := make([]bool, len(plans))
	for i, p := range plans {
		if emitted[i] {
			continue
		}
		if p.PackageName == "" || p.RequiredVersion == "" {
			out = append(out, p)
			emitted[i] = true
			continue
		}
		k := key{p.ProjectDir, p.PackageName}
		members := groups[k]
		if len(members) == 1 {
			out = append(out, p)
			emitted[i] = true
			continue
		}
		// Find the member with the max RequiredVersion (semver). Ties
		// broken by severity, then by first occurrence (stable).
		winnerIdx := members[0]
		for _, m := range members[1:] {
			if compareRequired(plans[m].RequiredVersion, plans[winnerIdx].RequiredVersion) > 0 {
				winnerIdx = m
			} else if compareRequired(plans[m].RequiredVersion, plans[winnerIdx].RequiredVersion) == 0 &&
				severityRank(plans[m].Severity) > severityRank(plans[winnerIdx].Severity) {
				winnerIdx = m
			}
		}
		merged := plans[winnerIdx]
		for _, m := range members {
			if severityRank(plans[m].Severity) > severityRank(merged.Severity) {
				merged.Severity = plans[m].Severity
			}
		}
		seenIDs := map[string]struct{}{}
		for _, m := range members {
			for _, id := range plans[m].CoveredVulnIDs {
				if id != "" {
					seenIDs[id] = struct{}{}
				}
			}
			if plans[m].VulnID != "" {
				seenIDs[plans[m].VulnID] = struct{}{}
			}
			emitted[m] = true
		}
		ids := make([]string, 0, len(seenIDs))
		for id := range seenIDs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		merged.CoveredVulnIDs = ids
		if len(members) > 1 {
			merged.Description = fmt.Sprintf("Upgrade %s in %s past %d CVEs to ^%s (headline: %s)",
				merged.PackageName, merged.ProjectDir, len(members), merged.RequiredVersion, merged.VulnID)
		}
		out = append(out, merged)
	}
	return out
}

// compareRequired compares two version strings for "which is higher"
// using a tiny in-package semver parser. Returns -1 / 0 / 1. Strings
// that don't parse compare lexicographically as a fallback — better
// than crashing, and the dedup is robust to it (the lex-fallback only
// matters when both inputs are unparseable, which doesn't happen for
// real OSV fixed-version data).
func compareRequired(a, b string) int {
	av, aok := parseRequiredSemver(a)
	bv, bok := parseRequiredSemver(b)
	if !aok || !bok {
		switch {
		case a < b:
			return -1
		case a > b:
			return 1
		}
		return 0
	}
	switch {
	case av[0] != bv[0]:
		if av[0] < bv[0] {
			return -1
		}
		return 1
	case av[1] != bv[1]:
		if av[1] < bv[1] {
			return -1
		}
		return 1
	case av[2] != bv[2]:
		if av[2] < bv[2] {
			return -1
		}
		return 1
	}
	return 0
}

// parseRequiredSemver is a deliberately tiny semver parser (no
// dependency on internal/osv to keep this package leaf-y). Accepts
// "X", "X.Y", "X.Y.Z", with optional leading "v" and trailing
// `-prerelease` / `+build` (which we strip and ignore). Anything
// non-numeric in a segment returns ok=false.
func parseRequiredSemver(s string) ([3]int, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	for i, c := range s {
		if c == '-' || c == '+' {
			s = s[:i]
			break
		}
	}
	if s == "" {
		return [3]int{}, false
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n := 0
		for _, r := range p {
			if r < '0' || r > '9' {
				return [3]int{}, false
			}
			n = n*10 + int(r-'0')
		}
		out[i] = n
	}
	return out, true
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}
