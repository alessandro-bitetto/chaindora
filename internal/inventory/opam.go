package inventory

import (
	"os"
	"strings"
)

// parseOpamLock parses an opam.lock file (or any *.opam file with
// pin-depends entries). Opam has multiple lockfile dialects; we
// handle the common case of a `depends:` array with package@version
// or package {= "version"} entries.
func parseOpamLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := string(data)
	// Find "depends: [" block.
	idx := strings.Index(s, "depends:")
	if idx < 0 {
		return nil, nil
	}
	rest := s[idx:]
	open := strings.Index(rest, "[")
	if open < 0 {
		return nil, nil
	}
	depth := 0
	end := -1
	for i := open; i < len(rest); i++ {
		switch rest[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end != -1 {
			break
		}
	}
	if end <= open {
		return nil, nil
	}
	body := rest[open+1 : end]
	seen := map[string]struct{}{}
	var out []Package
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		// `"name" {= "version"}` or `"name" {>= "0.0"}`.
		if !strings.HasPrefix(trimmed, `"`) {
			continue
		}
		closeQuote := strings.Index(trimmed[1:], `"`)
		if closeQuote < 0 {
			continue
		}
		name := trimmed[1 : 1+closeQuote]
		version := ""
		if i := strings.Index(trimmed, `{=`); i >= 0 {
			rest := trimmed[i+2:]
			if q1 := strings.Index(rest, `"`); q1 >= 0 {
				vrest := rest[q1+1:]
				if q2 := strings.Index(vrest, `"`); q2 >= 0 {
					version = vrest[:q2]
				}
			}
		}
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemOpam,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemOpam, name, version),
			SourcePath: path,
		})
	}
	return out, nil
}
