package inventory

import (
	"os"

	"gopkg.in/yaml.v3"
)

// parsePubspecLock parses pubspec.lock — Dart/Flutter's lockfile
// (YAML). Schema:
//
//	packages:
//	  http:
//	    dependency: "direct main"
//	    description:
//	      name: http
//	      url: "https://pub.dev"
//	      sha256: "abc..."
//	    source: hosted
//	    version: "1.2.0"
//
// We only emit hosted (pub.dev) packages — git / path / sdk
// sources are out of scope for OSV/registry lookups.
func parsePubspecLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]struct {
			Source      string `yaml:"source"`
			Version     string `yaml:"version"`
			Description struct {
				Name   string `yaml:"name"`
				Sha256 string `yaml:"sha256"`
			} `yaml:"description"`
		} `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	for k, entry := range lock.Packages {
		if entry.Version == "" {
			continue
		}
		if entry.Source != "" && entry.Source != "hosted" {
			continue
		}
		name := entry.Description.Name
		if name == "" {
			name = k
		}
		key := name + "@" + entry.Version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if entry.Description.Sha256 != "" {
			integrity = "sha256:" + entry.Description.Sha256
		}
		out = append(out, Package{
			Ecosystem:  EcosystemPub,
			Name:       name,
			Version:    entry.Version,
			PURL:       PURL(EcosystemPub, name, entry.Version),
			SourcePath: path,
			Integrity:  integrity,
		})
	}
	return out, nil
}
