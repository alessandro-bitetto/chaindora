package inventory

import (
	"os"
	"strings"
)

// parseGoMod parses a `go.mod` file and emits one Package per `require`
// entry. Both single-line and grouped `require (...)` blocks are supported.
// `// indirect` annotations are kept (indirect deps are still in the build
// graph and OSV catalogs them under the same Go ecosystem).
func parseGoMod(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Package
	seen := map[string]struct{}{}
	inBlock := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// Strip inline `//` comments (but preserve "// indirect" which is
		// after the version, so the version field stays intact).
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}
		switch {
		case strings.HasPrefix(line, "require ("):
			inBlock = true
			continue
		case line == ")" && inBlock:
			inBlock = false
			continue
		}

		var entry string
		switch {
		case inBlock:
			entry = line
		case strings.HasPrefix(line, "require "):
			entry = strings.TrimSpace(strings.TrimPrefix(line, "require"))
		default:
			continue
		}
		fields := strings.Fields(entry)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		version := fields[1]
		// Skip pseudo-empty placeholders (e.g. left over from "replace" blocks
		// that we don't parse here).
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemGoModules,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemGoModules, name, version),
			SourcePath: path,
		})
	}
	return out, nil
}
