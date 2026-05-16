package inventory

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// parseStackYamlLock parses Haskell's stack.yaml.lock. Each
// `packages:` entry has a `completed.hackage` string of shape
// "<name>-<version>@sha256:<hash>,<size>" plus a `completed.pantry-tree.sha256`
// for the Hackage content hash.
func parseStackYamlLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages []struct {
			Completed struct {
				Hackage    string `yaml:"hackage"`
				PantryTree struct {
					Sha256 string `yaml:"sha256"`
				} `yaml:"pantry-tree"`
			} `yaml:"completed"`
		} `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	for _, p := range lock.Packages {
		spec := p.Completed.Hackage
		if spec == "" {
			continue
		}
		// Strip "@sha256:..." suffix.
		if i := strings.Index(spec, "@"); i >= 0 {
			spec = spec[:i]
		}
		dash := strings.LastIndex(spec, "-")
		if dash <= 0 {
			continue
		}
		name := spec[:dash]
		version := spec[dash+1:]
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if p.Completed.PantryTree.Sha256 != "" {
			integrity = "sha256:" + p.Completed.PantryTree.Sha256
		}
		out = append(out, Package{
			Ecosystem:  EcosystemHackage,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemHackage, name, version),
			SourcePath: path,
			Integrity:  integrity,
		})
	}
	return out, nil
}

// parseCabalProjectFreeze parses cabal.project.freeze. Format:
//
//	constraints: any.aeson ==2.1.2.1,
//	             any.base ==4.18.0.0,
//	             ...
//
// cabal.project.freeze carries version pins only — no content
// hashes — so Integrity stays empty. Republish-guard won't fire
// for cabal packages until a content-hash source is added.
func parseCabalProjectFreeze(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := string(data)
	if i := strings.Index(s, "constraints:"); i >= 0 {
		s = s[i+len("constraints:"):]
	}
	seen := map[string]struct{}{}
	var out []Package
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "any.") {
			continue
		}
		part = strings.TrimPrefix(part, "any.")
		fields := strings.Fields(part)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		ver := strings.TrimPrefix(fields[1], "==")
		if name == "" || ver == "" {
			continue
		}
		key := name + "@" + ver
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemHackage,
			Name:       name,
			Version:    ver,
			PURL:       PURL(EcosystemHackage, name, ver),
			SourcePath: path,
		})
	}
	return out, nil
}
