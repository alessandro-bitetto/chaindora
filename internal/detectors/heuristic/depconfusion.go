package heuristic

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// detectDepConfusion looks for scoped npm packages that an attacker could
// hijack via the Birsan 2021 dependency-confusion vector. Evidence-based as
// of v0.6.0: instead of flagging every scoped package as a possible risk
// (the v0.5.x shape-only heuristic, which produced 200+ false positives in
// the field), we gather three signals and fire only when they agree.
//
// A scoped package is at real risk when BOTH of these are true:
//
//  1. The scope is *private* to this project. We detect this by:
//       (a) a `@scope:registry=<not-npmjs>` line in the project's .npmrc,
//           or
//       (b) the package's lockfile entry's `resolved` URL points to a
//           non-public registry (Artifactory, GitHub Packages, GitLab,
//           AWS CodeArtifact, ...).
//
//  2. A package with the same name *also exists on public npm*. An
//     attacker can register the colliding name and serve a malicious
//     version. Verified via registries.Probe.Exists.
//
// When 1 is false the package is treated as a public scope (e.g.
// @vitejs/plugin-react, @aws-sdk/client-s3) and not surfaced.
//
// When 1 is true but 2 is false we emit MEDIUM "defensively register
// this name" — the scope can be claimed later. When both are true we
// emit CRITICAL "attacker can hijack right now".
func detectDepConfusion(ctx context.Context, inv *inventory.Inventory, scanRoot string, cfg Config) []findings.Finding {
	if inv == nil {
		return nil
	}
	_, scopedRegistries := readNpmrcScopes(scanRoot)

	npm := cfg.npm()
	var out []findings.Finding
	seenScope := map[string]bool{}

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

		// Evidence 1a: .npmrc maps this scope to a non-public registry.
		// Evidence 1b: lockfile recorded a non-public resolved URL.
		private := scopedRegistries[scope] || isPrivateResolvedURL(p.ResolvedURL)
		if !private {
			continue
		}
		// Dedupe per scope — the user only needs one notification per
		// vulnerable scope, not one per package.
		if seenScope[scope] {
			continue
		}
		seenScope[scope] = true

		// Evidence 2: is the colliding name on public npm?
		publicExists, _ := npm.Exists(ctx, p.Name)

		var severity findings.Severity
		var msg string
		if publicExists {
			severity = findings.SeverityCritical
			msg = fmt.Sprintf(
				"Package %s resolves from a non-public registry, AND a package with the same name is published on public npm. "+
					"An attacker controlling that public package can ship malware to anyone whose registry config falls back to npm. "+
					"Action: verify your .npmrc scope mapping is enforced in CI, and consider claiming the public name defensively.",
				p.Name,
			)
		} else {
			severity = findings.SeverityMedium
			msg = fmt.Sprintf(
				"Scope %s resolves from a private registry. The same name is NOT currently claimed on public npm — "+
					"an attacker could register it later and intercept any build whose registry fallback isn't locked down. "+
					"Defensively claim %s (empty placeholder) on the public registry.",
				scope, p.Name,
			)
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

// isPrivateResolvedURL reports whether the lockfile's `resolved` URL points
// to anything other than the public npm registry / its CDN. We treat any
// host that isn't a known npmjs.org host as private; intentionally
// conservative since the consequence of a false negative is just "no
// finding fired" (the user can still inspect their .npmrc manually).
func isPrivateResolvedURL(u string) bool {
	if u == "" {
		return false
	}
	low := strings.ToLower(u)
	if strings.Contains(low, "registry.npmjs.org") ||
		strings.Contains(low, "registry.npm.org") ||
		strings.Contains(low, "cdn.jsdelivr.net") ||
		strings.Contains(low, "unpkg.com") {
		return false
	}
	// Heuristic: any URL containing "://" with a non-public host is
	// treated as private. Exclude `file:` and `git+` which are local /
	// repo references and don't carry dep-confusion risk.
	if strings.HasPrefix(low, "file:") || strings.HasPrefix(low, "git+") {
		return false
	}
	return strings.Contains(low, "://")
}

// readNpmrcScopes parses scanRoot/.npmrc for `@scope:registry=URL` lines
// and returns (whether the file existed at all, the set of scopes mapped
// to a non-public registry). Scopes mapped explicitly to registry.npmjs.org
// are treated as public (not at risk).
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
		i := strings.Index(line, ":registry=")
		if i <= 0 {
			continue
		}
		scope := line[:i]
		registry := strings.TrimSpace(line[i+len(":registry="):])
		registry = strings.ToLower(registry)
		// Only flag scopes mapped to a private registry; explicit
		// public-npm mapping (e.g. `@types:registry=https://registry.npmjs.org/`)
		// is a public scope.
		if !strings.Contains(registry, "registry.npmjs.org") {
			scopes[scope] = true
		}
	}
	return true, scopes
}
