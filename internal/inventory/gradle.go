package inventory

import (
	"os"
	"strings"
)

// parseGradleLockfile parses gradle.lockfile — a flat list of
// "group:artifact:version=configs" lines. No content hashes
// (Gradle's dependency-verification.xml is the integrity source,
// stored separately and opt-in; not parsed here).
func parseGradleLockfile(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "empty=" {
			continue
		}
		// "group:artifact:version=conf1,conf2,..."
		eq := strings.Index(trimmed, "=")
		spec := trimmed
		if eq >= 0 {
			spec = trimmed[:eq]
		}
		parts := strings.Split(spec, ":")
		if len(parts) != 3 {
			continue
		}
		group, artifact, version := parts[0], parts[1], parts[2]
		if group == "" || artifact == "" || version == "" {
			continue
		}
		fullName := group + ":" + artifact
		key := fullName + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemMavenCentral,
			Name:       fullName,
			Version:    version,
			PURL:       PURL(EcosystemMavenCentral, fullName, version),
			SourcePath: path,
		})
	}
	return out, nil
}
