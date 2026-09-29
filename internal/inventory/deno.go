package inventory

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

func parseDenoLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	packages, err := ParseDenoLockData(data)
	for i := range packages {
		packages[i].SourcePath = path
	}
	return packages, err
}

// ParseDenoLockData reads npm identities from Deno lock versions 3, 4 and 5.
// Gate resolution and scan inventory share this parser so format support cannot
// diverge. HTTPS/JSR entries remain outside npm inventory coverage.
func ParseDenoLockData(data []byte) ([]Package, error) {
	var lock struct {
		Version string          `json:"version"`
		NPM     json.RawMessage `json:"npm"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	type entry struct {
		Integrity string `json:"integrity"`
	}
	var packages map[string]entry
	switch lock.Version {
	case "3":
		var legacy struct {
			Packages map[string]entry `json:"packages"`
		}
		if len(lock.NPM) > 0 {
			if err := json.Unmarshal(lock.NPM, &legacy); err != nil {
				return nil, err
			}
		}
		packages = legacy.Packages
	case "4", "5":
		if len(lock.NPM) > 0 {
			if err := json.Unmarshal(lock.NPM, &packages); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("unsupported deno.lock version %q", lock.Version)
	}
	var keys []string
	for key := range packages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	seen := map[string]bool{}
	var out []Package
	for _, spec := range keys {
		// Use the first version separator, excluding an initial scope marker.
		// LastIndex would mistake @ inside a peer suffix for the version separator.
		start := 0
		if strings.HasPrefix(spec, "@") {
			start = 1
		}
		at := strings.Index(spec[start:], "@")
		if at < 0 {
			return nil, fmt.Errorf("invalid Deno npm identity %q", spec)
		}
		at += start
		name, version := spec[:at], spec[at+1:]
		if i := strings.IndexAny(version, "_("); i >= 0 {
			version = version[:i]
		}
		if name == "" || version == "" || strings.ContainsAny(version, "@ /\t\n") {
			return nil, fmt.Errorf("invalid Deno npm identity %q", spec)
		}
		key := name + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Package{Ecosystem: EcosystemNPM, Name: name, Version: version,
			PURL: PURL(EcosystemNPM, name, version), Integrity: packages[spec].Integrity})
	}
	return out, nil
}
