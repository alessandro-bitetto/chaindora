package heuristic

import (
	"context"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

// Config controls which sub-detectors run. The zero value enables every
// detector that doesn't need network access; FreshPopular.Enabled toggles
// the registry-querying detector on (off by default for offline-safe scans).
//
// As of v0.6.0, three heuristics (dep-confusion, typosquat, install-
// script) consult NPMProbe / PyPIProbe for ground-truth evidence
// from the upstream registries. When the probe is nil, those detectors
// fall back to the Noop probe and reduce to "no evidence available" —
// they don't fire false positives based on shape alone.
type Config struct {
	FreshPopular FreshPopularConfig
	// Excludes are directory basenames to skip during the install-script
	// filesystem walk. Same semantics as inventory.WithExcludes.
	Excludes []string
	// NPMProbe queries registry.npmjs.org for evidence the heuristics
	// need (existence, publish date, recent download count). nil → no
	// network calls.
	NPMProbe registries.Probe
	// PyPIProbe queries pypi.org / pypistats.org for the same shape.
	PyPIProbe registries.Probe
}

func (c Config) npm() registries.Probe {
	if c.NPMProbe != nil {
		return c.NPMProbe
	}
	return registries.Noop{}
}

func (c Config) pypi() registries.Probe {
	if c.PyPIProbe != nil {
		return c.PyPIProbe
	}
	return registries.Noop{}
}

// Detector runs behavioral heuristics that don't depend on external IOC
// lists. Sub-detectors emit findings tagged with detector "heuristic:<kind>".
type Detector struct {
	cfg Config
}

func New(cfg Config) *Detector { return &Detector{cfg: cfg} }

// Detect runs every sub-detector against the inventory and the scan tree.
func (d *Detector) Detect(ctx context.Context, inv *inventory.Inventory, scanRoot string) ([]findings.Finding, error) {
	var out []findings.Finding
	out = append(out, detectUnpinnedRefs(inv)...)
	out = append(out, detectCIShellPatterns(inv)...)
	out = append(out, detectInstallScripts(ctx, inv, scanRoot, d.cfg.Excludes, d.cfg)...)
	out = append(out, detectTyposquats(ctx, inv, d.cfg)...)
	out = append(out, detectDepConfusion(ctx, inv, scanRoot, d.cfg)...)
	out = append(out, detectFreshPopular(inv, d.cfg.FreshPopular)...)
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
