package heuristic

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// detectDepConfusion finds scoped npm packages that could be subject to a
// dependency-confusion attack. Without project-level knowledge of which
// scopes are private, this is a defensive heuristic: it flags every scoped
// package whose scope has no explicit `@scope:registry=...` line in the
// project's .npmrc.
//
// Severity:
//   - LOW if a .npmrc exists in scanRoot but doesn't pin this scope
//     (probably intentional, but worth surfacing)
//   - MEDIUM if no .npmrc exists at all (the scope resolves silently from
//     the public registry, which is the classic confusion-attack setup)
//
// Limitation: user-level ~/.npmrc is NOT checked. Most teams that ship
// private packages configure registries at the project level, but if you
// rely on user-level config the false positives here will be high.
func detectDepConfusion(inv *inventory.Inventory, scanRoot string) []findings.Finding {
	if inv == nil {
		return nil
	}
	hasNpmrc, scopedRegistries := readNpmrcScopes(scanRoot)

	var out []findings.Finding
	seen := map[string]bool{}
	for i := range inv.Packages {
		p := &inv.Packages[i]
		if p.Ecosystem != inventory.EcosystemNPM || !strings.HasPrefix(p.Name, "@") {
			continue
		}
		slash := strings.Index(p.Name, "/")
		if slash <= 0 {
			continue
		}
		scope := p.Name[:slash]
		if seen[scope] {
			continue
		}
		seen[scope] = true
		if scopedRegistries[scope] {
			continue
		}
		severity := findings.SeverityLow
		msg := fmt.Sprintf(
			"Scoped package %s resolves from the default npm registry. If %s is your private/internal scope, configure .npmrc with `%s:registry=...` to prevent dependency confusion.",
			p.Name, scope, scope,
		)
		if !hasNpmrc {
			severity = findings.SeverityMedium
			msg += " No .npmrc was found in the scan root."
		}
		out = append(out, findings.Finding{
			Detector:   "heuristic:dep-confusion",
			PURL:       p.PURL,
			Ecosystem:  p.Ecosystem,
			Name:       p.Name,
			Version:    p.Version,
			VulnID:     "HEUR-DEP-CONFUSION",
			Summary:    msg,
			Severity:   severity,
			SourcePath: p.SourcePath,
		})
	}
	return out
}

// readNpmrcScopes parses scanRoot/.npmrc for `@scope:registry=URL` lines and
// returns (whether the file existed at all, the set of explicitly-pinned
// scopes).
func readNpmrcScopes(scanRoot string) (bool, map[string]bool) {
	scopes := map[string]bool{}
	data, err := os.ReadFile(filepath.Join(scanRoot, ".npmrc"))
	if err != nil {
		return false, scopes
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "@") {
			continue
		}
		if i := strings.Index(line, ":registry="); i > 0 {
			scopes[line[:i]] = true
		}
	}
	return true, scopes
}
