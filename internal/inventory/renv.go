package inventory

import (
	"encoding/json"
	"os"
)

// parseRenvLock parses R's renv.lock JSON. Each package entry has
// Package / Version / Hash (typically md5 for CRAN, sha for
// Bioconductor or git commit for GitHub-sourced packages).
func parseRenvLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]struct {
			Package string `json:"Package"`
			Version string `json:"Version"`
			Source  string `json:"Source"`
			Hash    string `json:"Hash"`
		} `json:"Packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	for _, entry := range lock.Packages {
		name := entry.Package
		version := entry.Version
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if entry.Hash != "" {
			integrity = "renv-hash:" + entry.Hash
		}
		out = append(out, Package{
			Ecosystem:  EcosystemCRAN,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemCRAN, name, version),
			SourcePath: path,
			Integrity:  integrity,
		})
	}
	return out, nil
}
