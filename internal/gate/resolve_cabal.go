package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveCabalTree parses cabal.project.freeze — Cabal's pinned
// dependency list. Format:
//
//	constraints: any.aeson ==2.1.2.1,
//	             any.base ==4.18.0.0,
//	             ...
//
// cabal.project.freeze contains version pins only; no content
// hashes. We emit Integrity:"" — the republish guard won't fire
// for Hackage packages until either Cabal adds hash pinning OR
// we add a Hackage HTTP fetcher (like the rubygems / maven ones).
//
// cabalPath unused (cwd-only parser); kept for signature parity
// with other cwd-based resolvers.
func ResolveCabalTree(ctx context.Context, cabalPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("cabal resolver requires the user's project cwd")
	}
	data, err := os.ReadFile(filepath.Join(cwd, "cabal.project.freeze"))
	if err != nil {
		return nil, fmt.Errorf("read cabal.project.freeze: %w", err)
	}
	return parseCabalFreeze(data), nil
}

func parseCabalFreeze(data []byte) []PackageRef {
	seen := map[string]struct{}{}
	var refs []PackageRef
	// Strip `constraints:` header and joining-comma whitespace,
	// then split by commas.
	s := string(data)
	if i := strings.Index(s, "constraints:"); i >= 0 {
		s = s[i+len("constraints:"):]
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		// Each part is `any.<name> ==<version>` (or qualifier
		// flags like `setup.X`).
		if !strings.HasPrefix(part, "any.") {
			continue
		}
		part = strings.TrimPrefix(part, "any.")
		fields := strings.Fields(part)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		ver := fields[1]
		ver = strings.TrimPrefix(ver, "==")
		if name == "" || ver == "" {
			continue
		}
		key := name + "@" + ver
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, PackageRef{
			Ecosystem: "hackage",
			Name:      name,
			Version:   ver,
		})
	}
	return refs
}
