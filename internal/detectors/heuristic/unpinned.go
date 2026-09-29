package heuristic

import (
	"fmt"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// detectUnpinnedRefs flags packages in ecosystems where pinning to an
// immutable digest is supported but the ref is a mutable tag. Bitbucket
// pipes, CircleCI orbs, and Azure tasks are excluded because their version
// model is semver-only — there is no immutable-digest alternative to flag.
func detectUnpinnedRefs(inv *inventory.Inventory) []findings.Finding {
	if inv == nil {
		return nil
	}
	var out []findings.Finding
	for i := range inv.Packages {
		p := &inv.Packages[i]
		if !canPinByDigest(p.Ecosystem) || p.Pinned {
			continue
		}
		out = append(out, findings.Finding{
			Detector:  "heuristic:unpinned-ref",
			PURL:      p.PURL,
			Ecosystem: p.Ecosystem,
			Name:      p.Name,
			Version:   p.Version,
			VulnID:    "HEUR-UNPINNED-REF",
			Summary: fmt.Sprintf(
				"%s ref %q is not pinned to an immutable digest/SHA. A maintainer compromise of %s could swap in malicious code on the next run.",
				p.Ecosystem, p.Version, p.Name,
			),
			Severity:   findings.SeverityLow,
			SourcePath: p.SourcePath,
		})
	}
	return out
}

func canPinByDigest(e inventory.Ecosystem) bool {
	switch e {
	case inventory.EcosystemActions,
		inventory.EcosystemGitLabCI,
		inventory.EcosystemDocker:
		return true
	}
	return false
}
