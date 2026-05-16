package inventory

import (
	"os"
	"strings"
)

// parseZigZon parses Zig's build.zig.zon. Each dep entry has
// .name, .url, .hash; integrity is Zig's content-addressed hash.
func parseZigZon(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := string(data)
	idx := strings.Index(s, ".dependencies")
	if idx < 0 {
		return nil, nil
	}
	openBrace := strings.Index(s[idx:], "{")
	if openBrace < 0 {
		return nil, nil
	}
	depth := 0
	end := -1
	for i := idx + openBrace; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end != -1 {
			break
		}
	}
	if end <= idx+openBrace {
		return nil, nil
	}
	body := s[idx+openBrace+1 : end]
	seen := map[string]struct{}{}
	var out []Package
	var currentName, currentHash, currentVersion string
	flush := func() {
		defer func() { currentName, currentHash, currentVersion = "", "", "" }()
		if currentName == "" || currentHash == "" {
			return
		}
		if currentVersion == "" {
			currentVersion = "zig-content-addressed"
		}
		key := currentName + "@" + currentVersion
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemZig,
			Name:       currentName,
			Version:    currentVersion,
			PURL:       PURL(EcosystemZig, currentName, currentVersion),
			SourcePath: path,
			Integrity:  "zig:" + currentHash,
		})
	}
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ".") && strings.Contains(trimmed, "= .{") {
			flush()
			eq := strings.Index(trimmed, "=")
			currentName = strings.TrimSpace(strings.TrimPrefix(trimmed[:eq], "."))
			continue
		}
		if strings.HasPrefix(trimmed, ".hash") {
			if q1 := strings.Index(trimmed, `"`); q1 >= 0 {
				rest := trimmed[q1+1:]
				if q2 := strings.Index(rest, `"`); q2 >= 0 {
					currentHash = rest[:q2]
				}
			}
		}
		if strings.HasPrefix(trimmed, ".version") {
			if q1 := strings.Index(trimmed, `"`); q1 >= 0 {
				rest := trimmed[q1+1:]
				if q2 := strings.Index(rest, `"`); q2 >= 0 {
					currentVersion = rest[:q2]
				}
			}
		}
		if trimmed == "}," || trimmed == "}" {
			flush()
		}
	}
	flush()
	return out, nil
}
