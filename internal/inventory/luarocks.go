package inventory

import (
	"os"
	"strings"
)

// parseRockspec parses a Lua *.rockspec file. Rockspec is Lua
// source — we extract `package = "name"` and `version = "x.y.z-r"`
// scalar fields by line. No content hashes in stock rockspec.
func parseRockspec(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var name, version string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if v, ok := luaScalar(trimmed, "package"); ok {
			name = v
		}
		if v, ok := luaScalar(trimmed, "version"); ok {
			version = v
		}
	}
	if name == "" || version == "" {
		return nil, nil
	}
	return []Package{{
		Ecosystem:  EcosystemLuaRocks,
		Name:       name,
		Version:    version,
		PURL:       PURL(EcosystemLuaRocks, name, version),
		SourcePath: path,
	}}, nil
}

// luaScalar matches `key = "value"` or `key="value"` Lua syntax.
func luaScalar(line, key string) (string, bool) {
	if !strings.HasPrefix(line, key+" =") && !strings.HasPrefix(line, key+"=") {
		return "", false
	}
	eq := strings.Index(line, "=")
	v := strings.TrimSpace(line[eq+1:])
	v = strings.TrimSuffix(v, ",")
	v = strings.Trim(v, `"'`)
	return v, true
}
