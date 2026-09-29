package inventory

import (
	"os"
	"path/filepath"
	"strings"
)

// parseGoMod parses a `go.mod` file and emits one Package per `require`
// entry. Both single-line and grouped `require (...)` blocks are supported.
// `// indirect` annotations are kept (indirect deps are still in the build
// graph and OSV catalogs them under the same Go ecosystem).
//
// When a `go.sum` sits alongside `go.mod`, we populate Integrity with the
// `h1:` hash for each (module, version) — the cryptographic content hash
// Go records at module download time. Hash mismatches at scan-time vs the
// gate-cache then trigger the predictive republish-guard.
func parseGoMod(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Best-effort companion go.sum lookup. Missing/unreadable go.sum is
	// fine — we just leave Integrity empty.
	hashes := loadGoSumHashes(filepath.Join(filepath.Dir(path), "go.sum"))
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
			Integrity:  hashes[name+"@"+version],
		})
	}
	return out, nil
}

// loadGoSumHashes reads a go.sum file (if present) and returns a map
// of "module@version" → "h1:..." entries. Skips the "module/go.mod"
// h1 lines — those hash only the go.mod content, not the module bytes
// the build actually uses.
func loadGoSumHashes(path string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		mod, ver, hash := fields[0], fields[1], fields[2]
		// Skip "module v1.2.3/go.mod h1:..." entries.
		if strings.HasSuffix(ver, "/go.mod") {
			continue
		}
		if !strings.HasPrefix(hash, "h1:") {
			continue
		}
		out[mod+"@"+ver] = hash
	}
	return out
}
