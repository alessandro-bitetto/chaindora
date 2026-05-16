package inventory

import (
	"encoding/json"
	"os"
)

// parseNuGetPackagesLock parses packages.lock.json (the NuGet
// lockfile produced when a csproj has <RestorePackagesWithLockFile>
// true). Schema:
//
//	{
//	  "version": 1 | 2,
//	  "dependencies": {
//	    "net8.0": {
//	      "Newtonsoft.Json": {
//	        "type": "Direct" | "Transitive" | "Project",
//	        "resolved": "13.0.3",
//	        "contentHash": "base64-sha512"
//	      }
//	    }
//	  }
//	}
//
// Multiple target frameworks each get their own sub-map. We emit
// one Package per unique (name, version) across frameworks.
// Project-typed entries are skipped — those are sibling projects
// in the solution, not supply-chain risk.
func parseNuGetPackagesLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Dependencies map[string]map[string]struct {
			Type        string `json:"type"`
			Resolved    string `json:"resolved"`
			ContentHash string `json:"contentHash"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	for _, tfm := range lock.Dependencies {
		for name, entry := range tfm {
			if entry.Type == "Project" || entry.Resolved == "" {
				continue
			}
			key := name + "@" + entry.Resolved
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			integrity := ""
			if entry.ContentHash != "" {
				integrity = "sha512-" + entry.ContentHash
			}
			out = append(out, Package{
				Ecosystem:  EcosystemNuGet,
				Name:       name,
				Version:    entry.Resolved,
				PURL:       PURL(EcosystemNuGet, name, entry.Resolved),
				SourcePath: path,
				Integrity:  integrity,
			})
		}
	}
	return out, nil
}
