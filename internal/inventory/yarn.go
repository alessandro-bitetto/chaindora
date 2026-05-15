package inventory

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// parseYarnLock dispatches between the two yarn lockfile formats. Yarn v1
// uses a custom indentation-based format, while Berry (Yarn v2/v3+) emits
// valid YAML.
func parseYarnLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := string(data)
	head := text
	if len(head) > 256 {
		head = head[:256]
	}
	if strings.Contains(head, "yarn lockfile v1") {
		return parseYarnV1(text, path), nil
	}
	return parseYarnBerry(text, path)
}

// parseYarnV1 scans the legacy yarn.lock format line by line. Top-level
// entries start unindented and end with a colon; their version sits two
// spaces in on a "version" line.
func parseYarnV1(text, source string) []Package {
	var out []Package
	seen := map[string]struct{}{}
	var currentKeys []string

	for _, line := range strings.Split(text, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			currentKeys = parseYarnV1Keys(strings.TrimSuffix(line, ":"))
			continue
		}
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "version ") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(trimmed, "version"))
		v = strings.Trim(v, `"`)
		for _, k := range currentKeys {
			name := yarnNameFromV1Spec(k)
			if name == "" {
				continue
			}
			key := name + "@" + v
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, Package{
				Ecosystem:  EcosystemNPM,
				Name:       name,
				Version:    v,
				PURL:       PURL(EcosystemNPM, name, v),
				SourcePath: source,
			})
		}
		currentKeys = nil
	}
	return out
}

// parseYarnV1Keys handles top-level entry lines like:
//   lodash@^4.17.20
//   lodash@^4.17.20, lodash@^4.17.21
//   "@babel/code-frame@^7.0.0"
//   "@scope/a@^1.0.0", "@scope/a@^1.2.0"
func parseYarnV1Keys(line string) []string {
	var keys []string
	var current strings.Builder
	inQuote := false
	push := func() {
		k := strings.TrimSpace(current.String())
		k = strings.Trim(k, `"`)
		if k != "" {
			keys = append(keys, k)
		}
		current.Reset()
	}
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch ch {
		case '"':
			inQuote = !inQuote
		case ',':
			if !inQuote {
				push()
				continue
			}
			current.WriteByte(ch)
		default:
			current.WriteByte(ch)
		}
	}
	push()
	return keys
}

// yarnNameFromV1Spec extracts the package name from a v1 spec like
// "lodash@^4.17.20" or "@babel/code-frame@^7.0.0".
func yarnNameFromV1Spec(spec string) string {
	if strings.HasPrefix(spec, "@") {
		if i := strings.Index(spec[1:], "@"); i >= 0 {
			return spec[:i+1]
		}
		return ""
	}
	if i := strings.Index(spec, "@"); i > 0 {
		return spec[:i]
	}
	return ""
}

// parseYarnBerry decodes a Yarn v2+ (Berry) lockfile. Keys look like
//   "@babel/code-frame@npm:^7.0.0"
// and multiple aliases get comma-joined into a single YAML key string.
func parseYarnBerry(text, source string) ([]Package, error) {
	var raw map[string]struct {
		Version string `yaml:"version"`
	}
	if err := yaml.Unmarshal([]byte(text), &raw); err != nil {
		return nil, err
	}
	var out []Package
	seen := map[string]struct{}{}
	for k, entry := range raw {
		if k == "__metadata" || entry.Version == "" {
			continue
		}
		for _, spec := range strings.Split(k, ", ") {
			name := yarnNameFromBerrySpec(spec)
			if name == "" {
				continue
			}
			key := name + "@" + entry.Version
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, Package{
				Ecosystem:  EcosystemNPM,
				Name:       name,
				Version:    entry.Version,
				PURL:       PURL(EcosystemNPM, name, entry.Version),
				SourcePath: source,
			})
		}
	}
	return out, nil
}

// yarnNameFromBerrySpec parses Berry locator strings such as
//   lodash@npm:^4.17.20
//   "@babel/code-frame@npm:^7.0.0"
func yarnNameFromBerrySpec(spec string) string {
	if i := strings.Index(spec, "@npm:"); i > 0 {
		return spec[:i]
	}
	// Fallback for non-npm sources (workspace:, patch:, etc.) — try a generic
	// split that handles scoped names.
	if strings.HasPrefix(spec, "@") {
		if i := strings.Index(spec[1:], "@"); i >= 0 {
			return spec[:i+1]
		}
		return ""
	}
	if i := strings.Index(spec, "@"); i > 0 {
		return spec[:i]
	}
	return ""
}
