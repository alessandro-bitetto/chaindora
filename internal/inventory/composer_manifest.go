package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// parseComposerJSONManifest parses a composer.json file when no
// composer.lock is present alongside. Composer libraries (those
// published on Packagist for others to depend on) typically don't
// commit composer.lock — only applications do. This fallback covers
// the library case.
//
// Tradeoffs: same as the other manifest fallbacks — version
// constraints aren't resolved, so OSV-CVE matching and predictive
// behavioral checks silently no-op for range-versioned packages.
// OSV-MAL by name and incident-pack matching still work.
func parseComposerJSONManifest(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	emit := func(deps map[string]string) {
		for name, version := range deps {
			// Skip PHP itself and ext-* virtual packages (not real
			// packagist packages).
			if name == "php" || len(name) > 4 && name[:4] == "ext-" {
				continue
			}
			key := name + "@" + version
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, Package{
				Ecosystem:  EcosystemPackagist,
				Name:       name,
				Version:    version,
				PURL:       PURL(EcosystemPackagist, name, version),
				SourcePath: path,
			})
		}
	}
	emit(manifest.Require)
	emit(manifest.RequireDev)
	return out, nil
}

// hasComposerLockSibling reports whether composer.lock exists
// alongside composer.json.
func hasComposerLockSibling(composerJSONPath string) bool {
	sibling := filepath.Join(filepath.Dir(composerJSONPath), "composer.lock")
	_, err := os.Stat(sibling)
	return err == nil
}
