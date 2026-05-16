package inventory

import (
	"os"
	"strings"
)

// parseMixLock parses Elixir's mix.lock — an Erlang-syntax map
// of "pkg" → tuple. Hex-sourced entries look like:
//
//	%{
//	  "phoenix": {:hex, :phoenix, "1.7.10", "inner_hash", [...], [...], "hexpm", "outer_hash"},
//	  ...
//	}
//
// We want name (position 1 atom or map key), version (position 2),
// and outer sha256 (LAST quoted string in the tuple).
func parseMixLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, `"`) {
			continue
		}
		colon := strings.Index(trimmed, `":`)
		if colon < 0 {
			continue
		}
		name := strings.Trim(trimmed[:colon+1], `"`)
		rest := strings.TrimSpace(trimmed[colon+2:])
		if !strings.HasPrefix(rest, "{:hex,") {
			continue // git / path source — skip
		}
		// Strip outer braces and a trailing comma.
		body := strings.TrimPrefix(rest, "{")
		body = strings.TrimSuffix(body, ",")
		body = strings.TrimSuffix(body, "}")
		fields := splitMixTopLevelFields(body)
		if len(fields) < 3 {
			continue
		}
		version := strings.Trim(strings.TrimSpace(fields[2]), `"`)
		// Outer checksum: LAST quoted string in the tuple.
		outerSHA := ""
		for i := len(fields) - 1; i >= 3; i-- {
			f := strings.TrimSpace(fields[i])
			if strings.HasPrefix(f, `"`) && strings.HasSuffix(f, `"`) {
				outerSHA = strings.Trim(f, `"`)
				break
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
		integrity := ""
		if outerSHA != "" && isLowerHex(outerSHA) && len(outerSHA) >= 32 {
			integrity = "sha256:" + outerSHA
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

// splitMixTopLevelFields splits on commas at depth 0 only — commas
// inside [...] or {...} stay inside their field.
func splitMixTopLevelFields(s string) []string {
	var fields []string
	depth := 0
	start := 0
	for i, c := range s {
		switch c {
		case '[', '{', '(':
			depth++
		case ']', '}', ')':
			depth--
		case ',':
			if depth == 0 {
				fields = append(fields, s[start:i])
				start = i + 1
			}
		}
	}
	if start < len(s) {
		fields = append(fields, s[start:])
	}
	return fields
}

// isLowerHex reports whether s is non-empty lowercase hex.
func isLowerHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
