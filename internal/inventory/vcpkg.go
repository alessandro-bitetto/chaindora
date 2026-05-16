package inventory

import (
	"encoding/json"
	"os"
)

// parseVcpkgManifest parses vcpkg.json (manifest mode). Each
// dependency is either a bare string (name) or an object with
// {name, version>=}. The manifest's builtin-baseline (a git SHA)
// pins the registry state and acts as integrity.
func parseVcpkgManifest(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Dependencies    []json.RawMessage `json:"dependencies"`
		BuiltinBaseline string            `json:"builtin-baseline"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	for _, raw := range manifest.Dependencies {
		var name, version string
		if err := json.Unmarshal(raw, &name); err != nil {
			var obj struct {
				Name           string `json:"name"`
				VersionGreater string `json:"version>="`
				Version        string `json:"version"`
			}
			if err := json.Unmarshal(raw, &obj); err != nil {
				continue
			}
			name = obj.Name
			version = obj.Version
			if version == "" {
				version = obj.VersionGreater
			}
		}
		if name == "" {
			continue
		}
		if version == "" {
			version = "baseline:" + manifest.BuiltinBaseline
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if manifest.BuiltinBaseline != "" {
			integrity = "vcpkg-baseline:" + manifest.BuiltinBaseline
		}
		out = append(out, Package{
			Ecosystem:  EcosystemVcpkg,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemVcpkg, name, version),
			SourcePath: path,
			Integrity:  integrity,
		})
	}
	return out, nil
}
