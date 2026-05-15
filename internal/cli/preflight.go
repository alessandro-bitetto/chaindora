package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// preflightFilterSatisfied drops plans whose target package's currently
// installed version already satisfies the RequiredVersion in the same
// major. The point: when a saved plan from yesterday says "upgrade
// lodash to ^4.18.0" but the user already ran `npm install` since
// then, re-running the command is at best a no-op and at worst
// downgrades a newer transitive. The runner output ends up reporting
// every fix as "applied" when nothing actually moves.
//
// Scope (v0.8.1): only npm package-lock.json. Other ecosystems
// (yarn.lock, pnpm-lock.yaml, poetry.lock, uv.lock) fall through to
// the original behavior — the planning command runs and the package
// manager itself decides whether anything changes. Future work.
//
// Returns (kept plans, skipped count, lines describing skips).
func preflightFilterSatisfied(plans []findings.FixPlan) ([]findings.FixPlan, int, []string) {
	if len(plans) == 0 {
		return plans, 0, nil
	}
	cache := map[string]map[string]string{} // projectDir → pkgName → installedVersion
	kept := make([]findings.FixPlan, 0, len(plans))
	notes := make([]string, 0)
	skipped := 0
	for _, p := range plans {
		if p.PackageName == "" || p.RequiredVersion == "" || p.ProjectDir == "" {
			kept = append(kept, p)
			continue
		}
		installed, ok := installedVersionCached(cache, p.ProjectDir, p.PackageName)
		if !ok {
			kept = append(kept, p)
			continue
		}
		satisfied, ok := versionSatisfies(installed, p.RequiredVersion)
		if !ok {
			kept = append(kept, p)
			continue
		}
		if !satisfied {
			kept = append(kept, p)
			continue
		}
		skipped++
		notes = append(notes, fmt.Sprintf("  skipped %s @ %s (already at %s — satisfies required ^%s)",
			p.PackageName, p.ProjectDir, installed, p.RequiredVersion))
	}
	return kept, skipped, notes
}

// emitPreflightNotes prints the preflight skip diagnostics to stderr.
// Empty notes → no-op; we don't want to print a header when nothing
// was filtered.
func emitPreflightNotes(w io.Writer, notes []string, skipped int) {
	if skipped == 0 {
		return
	}
	fmt.Fprintf(w, "[chdora] preflight skipped %d already-satisfied fix(es):\n", skipped)
	for _, n := range notes {
		fmt.Fprintln(w, n)
	}
}

func installedVersionCached(cache map[string]map[string]string, projectDir, pkgName string) (string, bool) {
	if dir, ok := cache[projectDir]; ok {
		v, found := dir[pkgName]
		return v, found
	}
	versions := readNPMInstalled(projectDir)
	cache[projectDir] = versions
	v, found := versions[pkgName]
	return v, found
}

// readNPMInstalled reads <projectDir>/package-lock.json and returns a
// map of package name → installed version. We use lockfile v3's flat
// `packages` map (keys "node_modules/<name>") because it's the most
// reliable source of "the version actually installed on disk." The
// older v1 `dependencies` map is recursive and slow to walk; we don't
// need that fidelity for a preflight check.
//
// On any error (file missing, parse failure, unexpected schema) we
// return an empty map. Preflight then falls through and the regular
// command runs — never block a fix because the preflight is unsure.
func readNPMInstalled(projectDir string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(filepath.Join(projectDir, "package-lock.json"))
	if err != nil {
		return out
	}
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return out
	}
	for key, entry := range lock.Packages {
		if key == "" {
			continue
		}
		name := key
		if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
			name = key[i+len("node_modules/"):]
		}
		if name == "" || entry.Version == "" {
			continue
		}
		// First occurrence wins. Nested duplicates (the same package
		// at different depths) are fine to ignore because we only
		// care whether SOMETHING satisfies the pin — the top-level
		// install will satisfy peer deps either way.
		if _, exists := out[name]; !exists {
			out[name] = entry.Version
		}
	}
	return out
}

// versionSatisfies reports whether `installed` satisfies the caret
// constraint built from `required` (e.g. installed=4.17.21,
// required=4.17.20 → true because both are in major 4 and
// installed >= required).
//
// Returns (satisfied, ok) — ok=false means we couldn't parse one of
// the inputs and the caller should treat the constraint as unknown
// (and run the fix rather than skip).
func versionSatisfies(installed, required string) (bool, bool) {
	iv, iok := parsePackageLockSemver(installed)
	rv, rok := parsePackageLockSemver(required)
	if !iok || !rok {
		return false, false
	}
	if iv[0] != rv[0] {
		return false, true
	}
	if iv[1] != rv[1] {
		return iv[1] > rv[1], true
	}
	return iv[2] >= rv[2], true
}

// parsePackageLockSemver mirrors parseRequiredSemver in
// internal/findings — kept local so this file has no cross-package
// reach into findings internals. Same tolerance for "v" prefixes and
// trailing `-prerelease` / `+build` suffixes.
func parsePackageLockSemver(s string) ([3]int, bool) {
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
