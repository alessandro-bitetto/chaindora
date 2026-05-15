package inventory

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// parseCircleCIConfig parses a `.circleci/config.yml`. Captures the
// top-level `orbs:` map (`local_name: namespace/orb@version`).
func parseCircleCIConfig(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Orbs map[string]string `yaml:"orbs"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []Package
	seen := map[string]struct{}{}
	for _, ref := range doc.Orbs {
		i := strings.LastIndex(ref, "@")
		if i <= 0 {
			continue
		}
		name := ref[:i]
		version := ref[i+1:]
		key := name + "@" + version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemCircleCIOrbs,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemCircleCIOrbs, name, version),
			SourcePath: path,
		})
	}
	return out, nil
}
