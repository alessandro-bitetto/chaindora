package inventory

import (
	"os"
	"strings"
)

// parseCartfileResolved parses Carthage's Cartfile.resolved.
// Lines look like:
//
//	github "Alamofire/Alamofire" "5.6.4"
//	git "https://example.com/foo.git" "abc123def..."
//
// A 40-hex version is a git SHA — that's the integrity.
func parseCartfileResolved(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := splitCartfileFields(trimmed)
		if len(fields) < 3 {
			continue
		}
		source, spec, version := fields[0], fields[1], fields[2]
		if source != "github" && source != "git" && source != "binary" {
			continue
		}
		key := spec + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if len(version) == 40 && isLowerHex(strings.ToLower(version)) {
			integrity = "git:" + strings.ToLower(version)
		}
		out = append(out, Package{
			Ecosystem:  EcosystemCarthage,
			Name:       spec,
			Version:    version,
			PURL:       PURL(EcosystemCarthage, spec, version),
			SourcePath: path,
			Integrity:  integrity,
		})
	}
	return out, nil
}

func splitCartfileFields(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, c := range s {
		switch {
		case c == '"':
			inQuote = !inQuote
		case (c == ' ' || c == '\t') && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
