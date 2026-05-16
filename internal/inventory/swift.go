package inventory

import (
	"encoding/json"
	"os"
)

// parsePackageResolved parses Swift Package Manager's Package.resolved.
// Schema v2 (Swift 5.6+):
//
//	{
//	  "pins": [
//	    {"identity":"alamofire", "kind":"remoteSourceControl",
//	     "location":"https://github.com/Alamofire/Alamofire.git",
//	     "state":{"revision":"abc123","version":"5.8.0"}}
//	  ],
//	  "version": 2
//	}
//
// Integrity is the git revision (40-hex). Swift PM is git-anchored —
// republish-style attacks require force-pushing over a tag, which
// changes the revision and trips the republish-guard.
func parsePackageResolved(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var resolved struct {
		Pins []struct {
			Identity string `json:"identity"`
			Package  string `json:"package"` // v1 schema
			State    struct {
				Revision string `json:"revision"`
				Version  string `json:"version"`
				Branch   string `json:"branch"`
			} `json:"state"`
		} `json:"pins"`
	}
	if err := json.Unmarshal(data, &resolved); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	for _, p := range resolved.Pins {
		name := p.Identity
		if name == "" {
			name = p.Package
		}
		version := p.State.Version
		if version == "" {
			version = p.State.Branch
		}
		if version == "" {
			version = p.State.Revision
		}
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if p.State.Revision != "" {
			integrity = "git:" + p.State.Revision
		}
		out = append(out, Package{
			Ecosystem:  EcosystemSwift,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemSwift, name, version),
			SourcePath: path,
			Integrity:  integrity,
		})
	}
	return out, nil
}
