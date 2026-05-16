package inventory

import (
	"encoding/json"
	"os"
)

// parseNimbleLock parses Nim's nimble.lock JSON.
func parseNimbleLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]struct {
			Version     string `json:"version"`
			VcsRevision string `json:"vcsRevision"`
			Checksums   struct {
				Sha1 string `json:"sha1"`
			} `json:"checksums"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	for name, e := range lock.Packages {
		if e.Version == "" {
			continue
		}
		key := name + "@" + e.Version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if e.Checksums.Sha1 != "" {
			integrity = "sha1:" + e.Checksums.Sha1
		} else if e.VcsRevision != "" {
			integrity = "git:" + e.VcsRevision
		}
		out = append(out, Package{
			Ecosystem:  EcosystemNimble,
			Name:       name,
			Version:    e.Version,
			PURL:       PURL(EcosystemNimble, name, e.Version),
			SourcePath: path,
			Integrity:  integrity,
		})
	}
	return out, nil
}
