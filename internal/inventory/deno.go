package inventory

import (
	"encoding/json"
	"os"
	"strings"
)

// parseDenoLock parses deno.lock v3+. Schema:
//
//	{
//	  "version": "3",
//	  "remote": {"https://...": "sha256-hex"},
//	  "npm": {
//	    "packages": {
//	      "chalk@5.3.0": {"integrity": "sha512-..."}
//	    }
//	  }
//	}
//
// We emit npm-ecosystem packages from npm.packages. Remote HTTPS
// imports are not OSV-catalogued so we skip them here.
func parseDenoLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		NPM struct {
			Packages map[string]struct {
				Integrity string `json:"integrity"`
			} `json:"packages"`
		} `json:"npm"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	for spec, entry := range lock.NPM.Packages {
		atIdx := -1
		if strings.HasPrefix(spec, "@") {
			if i := strings.LastIndex(spec[1:], "@"); i > 0 {
				atIdx = i + 1
			}
		} else {
			atIdx = strings.LastIndex(spec, "@")
		}
		if atIdx <= 0 {
			continue
		}
		name := spec[:atIdx]
		version := spec[atIdx+1:]
		if i := strings.Index(version, "_"); i >= 0 {
			version = version[:i]
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemNPM,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemNPM, name, version),
			SourcePath: path,
			Integrity:  entry.Integrity,
		})
	}
	return out, nil
}
