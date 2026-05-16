package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ResolveVcpkgTree parses vcpkg.json (manifest mode) and emits
// PackageRefs for the declared dependencies. vcpkg's actual
// resolution model is more nuanced than a flat manifest read —
// transitive deps come from the registry baseline (a git SHA
// pointing into the vcpkg repo) plus overlay ports. A complete
// resolver would need to walk the registry tree at that baseline,
// which is heavy.
//
// This implementation covers DIRECT deps only — enough to apply
// the OSV / cooldown / publisher checkers (where applicable) and
// the republish guard against the baseline pin. Transitive
// coverage is a future enhancement.
//
// vcpkgPath unused (parser is cwd-only).
func ResolveVcpkgTree(ctx context.Context, vcpkgPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("vcpkg resolver requires the user's project cwd")
	}
	data, err := os.ReadFile(filepath.Join(cwd, "vcpkg.json"))
	if err != nil {
		return nil, fmt.Errorf("read vcpkg.json: %w", err)
	}
	return parseVcpkgManifest(data)
}

// parseVcpkgManifest reads vcpkg.json:
//
//	{
//	  "name": "myapp",
//	  "version": "1.0.0",
//	  "dependencies": ["fmt", "spdlog", {"name":"zlib","version>=":"1.3.0"}],
//	  "builtin-baseline": "abc123..."
//	}
//
// We emit one PackageRef per dep. The baseline SHA acts as a
// coarse integrity anchor — every dep under the same baseline
// resolves to the same registry-side commit.
func parseVcpkgManifest(data []byte) ([]PackageRef, error) {
	var manifest struct {
		Dependencies    []json.RawMessage `json:"dependencies"`
		BuiltinBaseline string            `json:"builtin-baseline"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse vcpkg.json: %w", err)
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, raw := range manifest.Dependencies {
		var name, version string
		// Dep can be a bare string or an object.
		if err := json.Unmarshal(raw, &name); err != nil {
			var obj struct {
				Name           string `json:"name"`
				VersionGreater string `json:"version>="`
				Version        string `json:"version"`
			}
			if err := json.Unmarshal(raw, &obj); err != nil {
				continue
			}
			name = obj.Name
			version = obj.Version
			if version == "" {
				version = obj.VersionGreater
			}
		}
		if name == "" {
			continue
		}
		if version == "" {
			// Without an explicit version, the baseline pin
			// implicitly defines what gets installed. Use the
			// baseline SHA as the version placeholder.
			version = "baseline:" + manifest.BuiltinBaseline
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if manifest.BuiltinBaseline != "" {
			integrity = "vcpkg-baseline:" + manifest.BuiltinBaseline
		}
		refs = append(refs, PackageRef{
			Ecosystem: "vcpkg",
			Name:      name,
			Version:   version,
			Direct:    true,
			Integrity: integrity,
		})
	}
	return refs, nil
}
