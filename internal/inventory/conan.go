package inventory

import (
	"encoding/json"
	"os"
	"strings"
)

// parseConanLock parses Conan 2.x's conan.lock. Schema:
//
//	{
//	  "version": "0.5",
//	  "requires": [
//	    "fmt/10.2.1#abc123...:package_id_hash"
//	  ]
//	}
//
// Each entry packs name/version/recipe-revision/package-id into a
// single ref string. We extract name + version + recipe revision
// as integrity.
func parseConanLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Requires      []string `json:"requires"`
		BuildRequires []string `json:"build_requires"`
		PythonRequires []string `json:"python_requires"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	all := append([]string{}, lock.Requires...)
	all = append(all, lock.BuildRequires...)
	all = append(all, lock.PythonRequires...)
	for _, ref := range all {
		name, version, revision := splitConanRef(ref)
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if revision != "" {
			integrity = "conan-rev:" + revision
		}
		out = append(out, Package{
			Ecosystem:  EcosystemConan,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemConan, name, version),
			SourcePath: path,
			Integrity:  integrity,
		})
	}
	return out, nil
}

func splitConanRef(ref string) (name, version, revision string) {
	// Strip ":package_id_hash" suffix.
	if i := strings.Index(ref, ":"); i >= 0 {
		ref = ref[:i]
	}
	// Split off "#recipe_revision".
	if i := strings.Index(ref, "#"); i >= 0 {
		revision = ref[i+1:]
		ref = ref[:i]
	}
	// Strip "@user/channel".
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.Index(ref, "/"); i > 0 {
		name = ref[:i]
		version = ref[i+1:]
	} else {
		name = ref
	}
	return name, version, revision
}
