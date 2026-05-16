package inventory

import (
	"os"

	"gopkg.in/yaml.v3"
)

// parseCondaLock parses conda-lock.yml (the conda-lock tool's
// resolved-environment file). Each package entry has name,
// version, and a hash map with md5 / sha256.
func parseCondaLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Package []struct {
			Name    string `yaml:"name"`
			Version string `yaml:"version"`
			Hash    struct {
				Sha256 string `yaml:"sha256"`
				MD5    string `yaml:"md5"`
			} `yaml:"hash"`
		} `yaml:"package"`
	}
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	for _, e := range lock.Package {
		if e.Name == "" || e.Version == "" {
			continue
		}
		key := e.Name + "@" + e.Version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if e.Hash.Sha256 != "" {
			integrity = "sha256:" + e.Hash.Sha256
		} else if e.Hash.MD5 != "" {
			integrity = "md5:" + e.Hash.MD5
		}
		out = append(out, Package{
			Ecosystem:  EcosystemConda,
			Name:       e.Name,
			Version:    e.Version,
			PURL:       PURL(EcosystemConda, e.Name, e.Version),
			SourcePath: path,
			Integrity:  integrity,
		})
	}
	return out, nil
}
