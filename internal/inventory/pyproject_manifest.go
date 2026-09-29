package inventory

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// parsePyprojectManifest parses a pyproject.toml as a fallback
// when no resolved lockfile (poetry.lock / uv.lock / pdm.lock)
// exists alongside. Covers two common dependency layouts:
//
//   - PEP 621 / uv / pdm / setuptools — `[project].dependencies`
//     is an array of PEP 508 specifiers:
//       dependencies = ["requests>=2.31", "rich~=13.0"]
//
//   - Poetry — `[tool.poetry.dependencies]` is a table of
//     name → version-spec entries:
//       requests = "^2.31"
//       rich = {version = "^13.0", optional = true}
//
// We extract name + constraint string. Like the other manifest
// fallbacks, this gives inventory presence + name-level malicious
// matching but loses precision on version-specific checks.
func parsePyprojectManifest(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := string(data)
	seen := map[string]struct{}{}
	var out []Package

	add := func(name, version string) {
		if name == "" || name == "python" {
			return
		}
		canonical := normalizePyPIName(name)
		key := canonical + "@" + version
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemPyPI,
			Name:       canonical,
			Version:    version,
			PURL:       PURL(EcosystemPyPI, canonical, version),
			SourcePath: path,
		})
	}

	// Pass 1: PEP 621 dependencies array.
	for _, spec := range extractPEP621Dependencies(text) {
		name, constraint := splitPEP508(spec)
		add(name, constraint)
	}

	// Pass 2: [tool.poetry.dependencies] / [tool.poetry.dev-dependencies].
	for _, table := range []string{"tool.poetry.dependencies", "tool.poetry.dev-dependencies", "tool.poetry.group.dev.dependencies"} {
		for name, version := range extractPoetryDependencyTable(text, table) {
			add(name, version)
		}
	}
	return out, nil
}

// extractPEP621Dependencies pulls every PEP 508 specifier from the
// `dependencies = [...]` array under `[project]`. Tolerates multi-
// line arrays, quoted strings, trailing commas, comments.
func extractPEP621Dependencies(text string) []string {
	start := strings.Index(text, "[project]")
	if start < 0 {
		return nil
	}
	// Limit search to the [project] section — bail on next `[` table header.
	body := text[start:]
	if i := strings.Index(body[len("[project]"):], "\n["); i >= 0 {
		body = body[:len("[project]")+i]
	}
	// Find `dependencies = [` block within body.
	depStart := strings.Index(body, "dependencies")
	if depStart < 0 {
		return nil
	}
	rest := body[depStart:]
	open := strings.Index(rest, "[")
	if open < 0 {
		return nil
	}
	close := strings.Index(rest[open:], "]")
	if close < 0 {
		return nil
	}
	listBody := rest[open+1 : open+close]
	var specs []string
	sc := bufio.NewScanner(strings.NewReader(listBody))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSuffix(line, ",")
		line = strings.Trim(line, "\"'")
		if line == "" {
			continue
		}
		specs = append(specs, line)
	}
	return specs
}

// splitPEP508 separates "pkg>=1.2,<2.0" → ("pkg", ">=1.2,<2.0").
// Strips PEP 508 extras (`requests[security]`) and environment
// markers (`; python_version<"3.12"`).
func splitPEP508(spec string) (name, constraint string) {
	if i := strings.Index(spec, ";"); i >= 0 {
		spec = spec[:i]
	}
	spec = strings.TrimSpace(spec)
	// Strip extras.
	if i := strings.Index(spec, "["); i >= 0 {
		j := strings.Index(spec[i:], "]")
		if j >= 0 {
			spec = spec[:i] + spec[i+j+1:]
		}
	}
	// Split on first comparator.
	if i := strings.IndexAny(spec, "=<>!~"); i > 0 {
		return strings.TrimSpace(spec[:i]), strings.TrimSpace(spec[i:])
	}
	return strings.TrimSpace(spec), ""
}

// extractPoetryDependencyTable returns name → version-string for
// entries under a Poetry-style TOML table. Tolerates inline-table
// version values like `requests = {version = "^2.31"}`.
var poetryEntryRE = regexp.MustCompile(`(?m)^([\w\-\.]+)\s*=\s*(?:"([^"]+)"|'([^']+)'|\{[^}]*version\s*=\s*["']([^"']+)["'][^}]*\})`)

func extractPoetryDependencyTable(text, table string) map[string]string {
	header := "[" + table + "]"
	start := strings.Index(text, header)
	if start < 0 {
		return nil
	}
	rest := text[start+len(header):]
	if i := strings.Index(rest, "\n["); i >= 0 {
		rest = rest[:i]
	}
	out := map[string]string{}
	for _, m := range poetryEntryRE.FindAllStringSubmatch(rest, -1) {
		name := m[1]
		version := m[2]
		if version == "" {
			version = m[3]
		}
		if version == "" {
			version = m[4]
		}
		if name == "" || name == "python" {
			continue
		}
		out[name] = version
	}
	return out
}

// hasPythonLockSibling reports whether ANY recognized Python
// lockfile exists alongside the pyproject.toml. If so, the
// real lockfile parser wins.
func hasPythonLockSibling(pyprojectPath string) bool {
	dir := filepath.Dir(pyprojectPath)
	for _, lockName := range []string{"poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock"} {
		if _, err := os.Stat(filepath.Join(dir, lockName)); err == nil {
			return true
		}
	}
	return false
}
