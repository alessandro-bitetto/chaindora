package inventory

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type pnpmLockDoc struct {
	Packages map[string]pnpmPackageEntry `yaml:"packages"`
}

type pnpmPackageEntry struct {
	Integrity  string `yaml:"integrity"`
	Resolution struct {
		// Pre-v7 nested integrity here.
		Integrity string `yaml:"integrity"`
	} `yaml:"resolution"`
}

// ParsePnpmLock is the exported entry point for callers outside
// the inventory package (the integrity detector's lockfile-vs-disk
// check, etc.). Delegates to parsePnpmLock.
func ParsePnpmLock(path string) ([]Package, error) {
	return parsePnpmLock(path)
}

// parsePnpmLock parses a pnpm-lock.yaml. Package keys take forms like:
//   /lodash@4.17.21               (v6 + earlier)
//   /@babel/code-frame@7.10.4
//   /foo@1.0.0(peer@2.0.0)        (peer-dep suffix)
//   lodash@4.17.21                (v9 dropped the leading slash)
func parsePnpmLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc pnpmLockDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []Package
	seen := map[string]struct{}{}
	for k, entry := range doc.Packages {
		name, version := parsePnpmKey(k)
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		integrity := entry.Integrity
		if integrity == "" {
			integrity = entry.Resolution.Integrity
		}
		out = append(out, Package{
			Ecosystem:  EcosystemNPM,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemNPM, name, version),
			SourcePath: path,
			Integrity:  integrity,
		})
	}
	return out, nil
}

func parsePnpmKey(k string) (name, version string) {
	k = strings.TrimPrefix(k, "/")
	if i := strings.Index(k, "("); i > 0 {
		k = k[:i]
	}
	if strings.HasPrefix(k, "@") {
		i := strings.Index(k[1:], "@")
		if i < 0 {
			return "", ""
		}
		return k[:i+1], k[i+2:]
	}
	i := strings.LastIndex(k, "@")
	if i <= 0 {
		return "", ""
	}
	return k[:i], k[i+1:]
}
