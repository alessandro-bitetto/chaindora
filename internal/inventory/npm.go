package inventory

import (
	"encoding/json"
	"os"
	"strings"
)

type npmLockfile struct {
	Name            string                        `json:"name"`
	LockfileVersion int                           `json:"lockfileVersion"`
	Packages        map[string]npmPackageEntry    `json:"packages"`
	Dependencies    map[string]npmDependencyEntry `json:"dependencies"`
}

type npmPackageEntry struct {
	Version          string `json:"version"`
	HasInstallScript bool   `json:"hasInstallScript"`
	Resolved         string `json:"resolved"`
}

type npmDependencyEntry struct {
	Version      string                        `json:"version"`
	Dependencies map[string]npmDependencyEntry `json:"dependencies"`
}

// parseNPMPackageLock parses package-lock.json (v1/v2/v3). v2 and v3 use a
// flat "packages" map keyed by install path; v1 uses a recursive "dependencies"
// tree.
func parseNPMPackageLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock npmLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var out []Package
	seen := map[string]struct{}{}

	for k, v := range lock.Packages {
		if k == "" || v.Version == "" {
			continue
		}
		idx := strings.LastIndex(k, "node_modules/")
		if idx < 0 {
			continue
		}
		name := k[idx+len("node_modules/"):]
		key := name + "@" + v.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:        EcosystemNPM,
			Name:             name,
			Version:          v.Version,
			PURL:             PURL(EcosystemNPM, name, v.Version),
			SourcePath:       path,
			HasInstallScript: v.HasInstallScript,
			ResolvedURL:      v.Resolved,
		})
	}

	if len(out) == 0 && lock.Dependencies != nil {
		walkNPMv1(lock.Dependencies, path, seen, &out)
	}
	return out, nil
}

func walkNPMv1(deps map[string]npmDependencyEntry, source string, seen map[string]struct{}, out *[]Package) {
	for name, dep := range deps {
		if dep.Version != "" {
			key := name + "@" + dep.Version
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				*out = append(*out, Package{
					Ecosystem:  EcosystemNPM,
					Name:       name,
					Version:    dep.Version,
					PURL:       PURL(EcosystemNPM, name, dep.Version),
					SourcePath: source,
				})
			}
		}
		if dep.Dependencies != nil {
			walkNPMv1(dep.Dependencies, source, seen, out)
		}
	}
}
