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
	// Dispatch by which lockfile exists in projectDir.
	// One-time per directory: read whichever family's lockfile
	// is present, cache the result. We don't try to combine
	// state across ecosystems — a project rarely mixes them in
	// the same dir.
	versions := readInstalledForProject(projectDir)
	cache[projectDir] = versions
	v, found := versions[pkgName]
	return v, found
}

// readInstalledForProject picks the right parser based on which
// lockfile is present in projectDir. Tries in order: npm,
// pnpm, yarn, poetry, Pipfile, uv, Cargo, Gemfile. First match
// wins. Returns empty map when nothing is recognized (preflight
// then falls through; the regular command runs).
func readInstalledForProject(projectDir string) map[string]string {
	type readFn func(string) map[string]string
	candidates := []struct {
		file string
		read readFn
	}{
		{"package-lock.json", readNPMInstalled},
		{"pnpm-lock.yaml", readPnpmInstalled},
		{"yarn.lock", readYarnInstalled},
		{"poetry.lock", readPoetryInstalled},
		{"Pipfile.lock", readPipfileInstalled},
		{"uv.lock", readUVInstalled},
		{"Cargo.lock", readCargoInstalled},
		{"Gemfile.lock", readGemfileInstalled},
	}
	for _, c := range candidates {
		path := filepath.Join(projectDir, c.file)
		if _, err := os.Stat(path); err == nil {
			out := c.read(projectDir)
			if len(out) > 0 {
				return out
			}
		}
	}
	return map[string]string{}
}

// readPnpmInstalled parses pnpm-lock.yaml. The `packages:` map
// keys are `/name@version` (pnpm v7+) or `/name/version` (v5-6).
func readPnpmInstalled(projectDir string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(filepath.Join(projectDir, "pnpm-lock.yaml"))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		// Two indented spaces, ends with ':' — package key line.
		if !strings.HasPrefix(line, "  ") || !strings.HasSuffix(trimmed, ":") {
			continue
		}
		key := strings.TrimSuffix(trimmed, ":")
		key = strings.TrimSpace(key)
		key = strings.Trim(key, `"'`)
		if !strings.HasPrefix(key, "/") {
			continue
		}
		k := strings.TrimPrefix(key, "/")
		if i := strings.IndexAny(k, " ("); i >= 0 {
			k = k[:i]
		}
		// v7+ "/<name>@<version>" or v5-6 "/<name>/<version>".
		atIdx := -1
		if strings.HasPrefix(k, "@") {
			if i := strings.LastIndex(k[1:], "@"); i > 0 {
				atIdx = i + 1
			}
		} else {
			atIdx = strings.LastIndex(k, "@")
		}
		var name, version string
		if atIdx > 0 {
			name, version = k[:atIdx], k[atIdx+1:]
		} else if i := strings.LastIndex(k, "/"); i > 0 {
			name, version = k[:i], k[i+1:]
		}
		if name == "" || version == "" {
			continue
		}
		if _, exists := out[name]; !exists {
			out[name] = version
		}
	}
	return out
}

// readYarnInstalled parses yarn classic v1 lockfile. Same logic
// as the gate's parseYarnClassicLock but narrower (just the
// (name, version) pair).
func readYarnInstalled(projectDir string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(filepath.Join(projectDir, "yarn.lock"))
	if err != nil {
		return out
	}
	var currentName string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
			spec := strings.TrimSuffix(trimmed, ":")
			if i := strings.Index(spec, ","); i >= 0 {
				spec = spec[:i]
			}
			spec = strings.Trim(spec, `"`)
			atIdx := -1
			if strings.HasPrefix(spec, "@") {
				if i := strings.Index(spec[1:], "@"); i >= 0 {
					atIdx = i + 1
				}
			} else {
				atIdx = strings.LastIndex(spec, "@")
			}
			if atIdx > 0 {
				currentName = spec[:atIdx]
			}
			continue
		}
		if strings.HasPrefix(trimmed, "version ") {
			ver := strings.TrimSpace(strings.TrimPrefix(trimmed, "version"))
			ver = strings.Trim(ver, `"`)
			if currentName == "" || ver == "" {
				continue
			}
			if _, exists := out[currentName]; !exists {
				out[currentName] = ver
			}
		}
	}
	return out
}

// readPoetryInstalled parses poetry.lock's `[[package]]` stanzas.
// Same TOML-by-hand strategy as the gate's Cargo parser.
func readPoetryInstalled(projectDir string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(filepath.Join(projectDir, "poetry.lock"))
	if err != nil {
		return out
	}
	blocks := strings.Split(string(data), "[[package]]")
	for _, b := range blocks[1:] {
		name := tomlField(b, "name")
		version := tomlField(b, "version")
		if name != "" && version != "" {
			if _, exists := out[name]; !exists {
				out[name] = version
			}
		}
	}
	return out
}

// readUVInstalled parses uv.lock — uv uses TOML-shaped lockfile
// with `[[package]]` blocks like poetry.
func readUVInstalled(projectDir string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(filepath.Join(projectDir, "uv.lock"))
	if err != nil {
		return out
	}
	blocks := strings.Split(string(data), "[[package]]")
	for _, b := range blocks[1:] {
		name := tomlField(b, "name")
		version := tomlField(b, "version")
		if name != "" && version != "" {
			if _, exists := out[name]; !exists {
				out[name] = version
			}
		}
	}
	return out
}

// readPipfileInstalled parses Pipfile.lock (JSON, with `default`
// and `develop` sections each keyed by package name).
func readPipfileInstalled(projectDir string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(filepath.Join(projectDir, "Pipfile.lock"))
	if err != nil {
		return out
	}
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return out
	}
	for name, entry := range lock.Default {
		v := strings.TrimPrefix(entry.Version, "==")
		if v != "" {
			out[name] = v
		}
	}
	for name, entry := range lock.Develop {
		v := strings.TrimPrefix(entry.Version, "==")
		if _, exists := out[name]; !exists && v != "" {
			out[name] = v
		}
	}
	return out
}

// readCargoInstalled parses Cargo.lock's [[package]] blocks.
func readCargoInstalled(projectDir string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(filepath.Join(projectDir, "Cargo.lock"))
	if err != nil {
		return out
	}
	blocks := strings.Split(string(data), "[[package]]")
	for _, b := range blocks[1:] {
		name := tomlField(b, "name")
		version := tomlField(b, "version")
		// Skip non-crates.io sources (local path, git deps).
		source := tomlField(b, "source")
		if !strings.Contains(source, "crates.io") {
			continue
		}
		if name != "" && version != "" {
			if _, exists := out[name]; !exists {
				out[name] = version
			}
		}
	}
	return out
}

// readGemfileInstalled parses Bundler's Gemfile.lock. Same
// indentation-based parsing as the inventory module.
func readGemfileInstalled(projectDir string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(filepath.Join(projectDir, "Gemfile.lock"))
	if err != nil {
		return out
	}
	inGEM := false
	inSpecs := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if len(line) > 0 && line[0] != ' ' {
			inGEM = trimmed == "GEM"
			inSpecs = false
			continue
		}
		if !inGEM {
			continue
		}
		if trimmed == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}
		// 4-space indent + "name (version)" line.
		if !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "      ") {
			continue
		}
		open := strings.LastIndex(trimmed, "(")
		closeIdx := strings.LastIndex(trimmed, ")")
		if open < 0 || closeIdx < open {
			continue
		}
		name := strings.TrimSpace(trimmed[:open])
		version := strings.TrimSpace(trimmed[open+1 : closeIdx])
		if name == "" || version == "" {
			continue
		}
		if strings.ContainsAny(version, "~<>=") {
			continue // dependency constraint, not resolved version
		}
		if _, exists := out[name]; !exists {
			out[name] = version
		}
	}
	return out
}

// tomlField extracts `key = "value"` from a stanza body. Shared
// helper for poetry/uv/Cargo. Stops at the next `[` line.
func tomlField(block, key string) string {
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			break
		}
		if !strings.HasPrefix(trimmed, key+" = ") && !strings.HasPrefix(trimmed, key+"=") {
			continue
		}
		eq := strings.Index(trimmed, "=")
		v := strings.TrimSpace(trimmed[eq+1:])
		v = strings.Trim(v, `"`)
		return v
	}
	return ""
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
