package heuristic

import (
	"fmt"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// detectTyposquats flags inventory packages whose name is within Levenshtein
// distance 1 or 2 of a popular package, suggesting they may be typosquats.
// Skips:
//   - Packages already in the top-N list (they ARE the popular package)
//   - Scoped npm packages (covered by detectDepConfusion instead)
//   - Pairs where name length differs by more than 3 (likely unrelated)
func detectTyposquats(inv *inventory.Inventory) []findings.Finding {
	if inv == nil {
		return nil
	}
	var out []findings.Finding
	for i := range inv.Packages {
		p := &inv.Packages[i]
		var pool []string
		switch p.Ecosystem {
		case inventory.EcosystemNPM:
			pool = topNPM
		case inventory.EcosystemPyPI:
			pool = topPyPI
		default:
			continue
		}
		if strings.HasPrefix(p.Name, "@") {
			continue
		}
		if isInList(p.Name, pool) {
			continue
		}
		for _, popular := range pool {
			if absInt(len(p.Name)-len(popular)) > 3 {
				continue
			}
			d := levenshtein(p.Name, popular)
			if d == 0 || d > 2 {
				continue
			}
			out = append(out, findings.Finding{
				Detector:  "heuristic:typosquat",
				PURL:      p.PURL,
				Ecosystem: p.Ecosystem,
				Name:      p.Name,
				Version:   p.Version,
				VulnID:    "HEUR-TYPOSQUAT",
				Summary: fmt.Sprintf(
					"%s package %q is %d edit(s) away from popular package %q. Verify this is not a typosquat.",
					p.Ecosystem, p.Name, d, popular,
				),
				Severity:   findings.SeverityMedium,
				SourcePath: p.SourcePath,
			})
			break
		}
	}
	return out
}
