package inventory

import (
	"os"
	"strings"
)

// parseRebar3Lock parses Erlang/rebar3's rebar.lock. Similar
// Erlang-tuple format to mix.lock; sha256 lives in a separate
// pkg_hash section at the end.
func parseRebar3Lock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := string(data)
	checksums := map[string]string{}
	if idx := strings.Index(s, "{pkg_hash,["); idx >= 0 {
		block := s[idx+len("{pkg_hash,["):]
		for _, row := range strings.Split(block, "{") {
			row = strings.TrimSpace(row)
			if row == "" || strings.HasPrefix(row, "pkg_hash") {
				continue
			}
			parts := extractRebarBinaries(row)
			if len(parts) >= 2 {
				checksums[parts[0]] = strings.ToLower(parts[1])
			}
		}
	}
	seen := map[string]struct{}{}
	var out []Package
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "{<<") {
			continue
		}
		parts := extractRebarBinaries(trimmed)
		if len(parts) < 2 {
			continue
		}
		name := parts[0]
		version := parts[len(parts)-1]
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if h := checksums[name]; h != "" {
			integrity = "sha256:" + h
		}
		out = append(out, Package{
			Ecosystem:  EcosystemHex,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemHex, name, version),
			SourcePath: path,
			Integrity:  integrity,
		})
	}
	return out, nil
}

func extractRebarBinaries(s string) []string {
	var out []string
	for {
		i := strings.Index(s, `<<"`)
		if i < 0 {
			break
		}
		j := strings.Index(s[i+3:], `"`)
		if j < 0 {
			break
		}
		out = append(out, s[i+3:i+3+j])
		s = s[i+3+j+1:]
	}
	return out
}
