package inventory

import (
	"encoding/json"
	"os"
)

// parseComposerLock parses composer.lock (the PHP/Composer
// lockfile). Schema:
//
//	{
//	  "packages": [
//	    {"name": "vendor/pkg", "version": "1.2.3", "dist": {"shasum": "sha1hex"}, "type": "library"},
//	    ...
//	  ],
//	  "packages-dev": [ ... ]
//	}
//
// Composer's dist.shasum is sha1 of the .zip tarball. Older
// composer.lock files emit "v1.2.3" with a leading 'v' — we keep
// the version as-recorded so downstream PURL builders stay
// consistent with what registries expect.
func parseComposerLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages    []composerLockEntry `json:"packages"`
		PackagesDev []composerLockEntry `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	add := func(entries []composerLockEntry) {
		for _, e := range entries {
			if e.Name == "" || e.Version == "" {
				continue
			}
			key := e.Name + "@" + e.Version
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			integrity := ""
			if e.Dist.Shasum != "" {
				integrity = "sha1:" + e.Dist.Shasum
			}
			out = append(out, Package{
				Ecosystem:  EcosystemPackagist,
				Name:       e.Name,
				Version:    e.Version,
				PURL:       PURL(EcosystemPackagist, e.Name, e.Version),
				SourcePath: path,
				Integrity:  integrity,
			})
		}
	}
	add(lock.Packages)
	add(lock.PackagesDev)
	return out, nil
}

type composerLockEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Shasum string `json:"shasum"`
	} `json:"dist"`
}
