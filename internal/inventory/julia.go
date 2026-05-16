package inventory

import (
	"os"
	"strings"
)

// parseJuliaManifest parses Julia's Manifest.toml. Schema (v1
// or v2): each [[deps.NAME]] (v2) or [[NAME]] (v1) block has
// version + git-tree-sha1.
func parseJuliaManifest(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	chunks := strings.Split(string(data), "[[")
	for _, c := range chunks[1:] {
		end := strings.Index(c, "]]")
		if end <= 0 {
			continue
		}
		header := c[:end]
		body := c[end+2:]
		if i := strings.Index(body, "\n["); i >= 0 {
			body = body[:i]
		}
		name := strings.TrimPrefix(header, "deps.")
		version := tomlField(body, "version")
		sha := tomlField(body, "git-tree-sha1")
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if sha != "" {
			integrity = "git-tree-sha1:" + sha
		}
		out = append(out, Package{
			Ecosystem:  EcosystemJulia,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemJulia, name, version),
			SourcePath: path,
			Integrity:  integrity,
		})
	}
	return out, nil
}

// tomlField extracts `key = "value"` from a TOML stanza body.
// Used by Julia + (future) other TOML-shaped parsers.
func tomlField(block, key string) string {
	for _, line := range strings.Split(block, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, key+" = ") && !strings.HasPrefix(t, key+"=") {
			continue
		}
		eq := strings.Index(t, "=")
		v := strings.TrimSpace(t[eq+1:])
		return strings.Trim(v, `"`)
	}
	return ""
}
