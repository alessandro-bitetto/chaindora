package inventory

import (
	"os"
	"strings"
)

// parseCpanfileSnapshot parses Perl/Carton's cpanfile.snapshot.
// Distribution lines under DISTRIBUTIONS look like:
//
//	DISTRIBUTIONS
//	  Plack-1.0050
//	    pathname: M/MI/MIYAGAWA/Plack-1.0050.tar.gz
//
// No content hash in the snapshot format. Integrity stays empty.
func parseCpanfileSnapshot(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	inDistributions := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if line == "DISTRIBUTIONS" {
			inDistributions = true
			continue
		}
		if !inDistributions {
			continue
		}
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "    ") {
			continue
		}
		dash := strings.LastIndex(trimmed, "-")
		if dash <= 0 {
			continue
		}
		name := trimmed[:dash]
		version := trimmed[dash+1:]
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemCPAN,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemCPAN, name, version),
			SourcePath: path,
		})
	}
	return out, nil
}
