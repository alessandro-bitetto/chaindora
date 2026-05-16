package inventory

import (
	"encoding/json"
	"os"
)

// parseElmJSON parses Elm's elm.json. dependencies.direct and
// dependencies.indirect are maps of "owner/pkg" → version. No
// content hashes.
func parseElmJSON(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Dependencies struct {
			Direct   map[string]string `json:"direct"`
			Indirect map[string]string `json:"indirect"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	emit := func(deps map[string]string) {
		for name, version := range deps {
			key := name + "@" + version
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, Package{
				Ecosystem:  EcosystemElm,
				Name:       name,
				Version:    version,
				PURL:       PURL(EcosystemElm, name, version),
				SourcePath: path,
			})
		}
	}
	emit(manifest.Dependencies.Direct)
	emit(manifest.Dependencies.Indirect)
	return out, nil
}
