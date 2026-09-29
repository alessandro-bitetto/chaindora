package inventory

import (
	"encoding/json"
	"os"
	"strings"
)

type pipfileEntry struct {
	Version string   `json:"version"`
	Hashes  []string `json:"hashes"`
}

type pipfileLockDoc struct {
	Default map[string]pipfileEntry `json:"default"`
	Develop map[string]pipfileEntry `json:"develop"`
}

// ParsePipfileLock is the exported entry point used by the integrity
// detector's lockfile-vs-disk drift check.
func ParsePipfileLock(path string) ([]Package, error) {
	return parsePipfileLock(path)
}

// parsePipfileLock parses Pipfile.lock JSON. Each entry's "version" field is
// a constraint string like "==1.26.4"; entries without an exact `==` pin are
// skipped.
func parsePipfileLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc pipfileLockDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []Package
	seen := map[string]struct{}{}
	add := func(m map[string]pipfileEntry) {
		for name, entry := range m {
			v := strings.TrimPrefix(entry.Version, "==")
			if v == entry.Version || v == "" {
				continue
			}
			nn := normalizePyPIName(name)
			key := nn + "@" + v
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			integrity := ""
			if len(entry.Hashes) > 0 {
				integrity = entry.Hashes[0]
			}
			out = append(out, Package{
				Ecosystem:  EcosystemPyPI,
				Name:       nn,
				Version:    v,
				PURL:       PURL(EcosystemPyPI, nn, v),
				SourcePath: path,
				Integrity:  integrity,
			})
		}
	}
	add(doc.Default)
	add(doc.Develop)
	return out, nil
}
