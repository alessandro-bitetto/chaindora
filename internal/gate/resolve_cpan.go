package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveCpanTree parses cpanfile.snapshot (Perl/Carton's lock
// equivalent). Format:
//
//	# carton snapshot format: version 1.0
//	DISTRIBUTIONS
//	  Plack-1.0050
//	    pathname: M/MI/MIYAGAWA/Plack-1.0050.tar.gz
//	    provides:
//	      Plack 1.0050
//	    requirements:
//	      Module::Build 0.38
//
// We extract distribution name + version. cpanfile.snapshot has
// no per-dist checksum in standard format; MetaCPAN does. We
// emit Integrity:"" — could be enriched via a MetaCPAN fetcher
// in a future pass.
//
// cpanmPath unused (parser is cwd-only).
func ResolveCpanTree(ctx context.Context, cpanmPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("CPAN resolver requires the user's project cwd")
	}
	data, err := os.ReadFile(filepath.Join(cwd, "cpanfile.snapshot"))
	if err != nil {
		return nil, fmt.Errorf("read cpanfile.snapshot: %w", err)
	}
	return parseCpanfileSnapshot(data), nil
}

func parseCpanfileSnapshot(data []byte) []PackageRef {
	seen := map[string]struct{}{}
	var refs []PackageRef
	inDistributions := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		// Section header at column 0.
		if line == "DISTRIBUTIONS" {
			inDistributions = true
			continue
		}
		if !inDistributions {
			continue
		}
		// Distribution lines are indented by 2 spaces; sub-fields
		// are indented further.
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "    ") {
			continue
		}
		// trimmed looks like "Plack-1.0050".
		dash := strings.LastIndex(trimmed, "-")
		if dash <= 0 {
			continue
		}
		name := trimmed[:dash]
		version := trimmed[dash+1:]
		// Skip distributions with non-version suffixes (e.g., "-TRIAL").
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, PackageRef{
			Ecosystem: "cpan",
			Name:      name,
			Version:   version,
		})
	}
	return refs
}
