package heuristic

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

// Typosquat evidence thresholds. Real typosquats are almost always:
//   - young (registered shortly before the attack), and
//   - low-traffic (no real ecosystem adoption — they exist to harvest the
//     occasional typo, not to build a user base).
//
// A Levenshtein-close package that has been on npm for years AND has 10k+
// weekly downloads is overwhelmingly likely to be a legitimate
// neighbour-name package (jsonparse vs json-parse, lodash.assign vs
// lodash.assignin, etc.) — flagging it generates pure false positives.
const (
	typosquatMaxAgeDays    = 90
	typosquatMaxDownloads7d = 1000
)

// detectTyposquats flags inventory packages whose name is Levenshtein-near
// a popular package AND for which registry evidence supports "this is
// suspiciously fresh and low-traffic." When no probe is configured
// (offline / --skip-registry), nothing fires — we'd rather under-report
// than swamp the user with shape-only guesses.
func detectTyposquats(ctx context.Context, inv *inventory.Inventory, cfg Config) []findings.Finding {
	if inv == nil {
		return nil
	}
	var out []findings.Finding
	for i := range inv.Packages {
		p := &inv.Packages[i]
		var pool []string
		var probe registries.Probe
		switch p.Ecosystem {
		case inventory.EcosystemNPM:
			pool = topNPM
			probe = cfg.npm()
		case inventory.EcosystemPyPI:
			pool = topPyPI
			probe = cfg.pypi()
		default:
			continue
		}
		if strings.HasPrefix(p.Name, "@") {
			// Scoped packages are covered by dep-confusion; typosquat
			// of a scoped name is implausible because the scope acts
			// as a namespace barrier.
			continue
		}
		if isInList(p.Name, pool) {
			continue
		}
		var nearest string
		var nearestDist int
		for _, popular := range pool {
			if absInt(len(p.Name)-len(popular)) > 3 {
				continue
			}
			d := levenshtein(p.Name, popular)
			if d == 0 || d > 2 {
				continue
			}
			if nearest == "" || d < nearestDist {
				nearest = popular
				nearestDist = d
			}
		}
		if nearest == "" {
			continue
		}

		// Evidence-gathering: how old and how popular is this name?
		pub, _ := probe.PublishedAt(ctx, p.Name)
		dl, _ := probe.DownloadsLast7d(ctx, p.Name)

		// If we can't get evidence (no probe / offline / probe error),
		// don't fire — we can't distinguish a real typosquat from
		// jsonparse-vs-json-parse based on shape alone.
		if pub.IsZero() && dl < 0 {
			continue
		}

		ageDays := -1
		if !pub.IsZero() {
			ageDays = int(time.Since(pub).Hours() / 24)
		}
		// Skip if it's mature AND has real adoption.
		if ageDays >= 0 && ageDays > typosquatMaxAgeDays && dl > typosquatMaxDownloads7d {
			continue
		}
		// Skip if it's just mature (years old) — even if downloads are
		// low. Old + obscure isn't typosquat-shaped.
		if ageDays > 365 {
			continue
		}

		var severity findings.Severity
		switch {
		case ageDays >= 0 && ageDays <= 7:
			severity = findings.SeverityHigh
		case ageDays >= 0 && ageDays <= 30:
			severity = findings.SeverityMedium
		default:
			severity = findings.SeverityLow
		}
		msg := fmt.Sprintf(
			"%s package %q is %d edit(s) away from popular package %q",
			p.Ecosystem, p.Name, nearestDist, nearest,
		)
		if ageDays >= 0 {
			msg += fmt.Sprintf(", first published %d day(s) ago", ageDays)
		}
		if dl >= 0 {
			msg += fmt.Sprintf(", %d downloads/week", dl)
		}
		msg += ". Verify this is the intended dependency."

		out = append(out, findings.Finding{
			Detector:   "heuristic:typosquat",
			PURL:       p.PURL,
			Ecosystem:  p.Ecosystem,
			Name:       p.Name,
			Version:    p.Version,
			VulnID:     "HEUR-TYPOSQUAT",
			Summary:    msg,
			Severity:   severity,
			SourcePath: p.SourcePath,
		})
	}
	return out
}
