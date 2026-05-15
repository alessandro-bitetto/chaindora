package heuristic

import (
	"context"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// Config controls which sub-detectors run. The zero value enables every
// detector that doesn't need network access; FreshPopular.Enabled toggles
// the registry-querying detector on (off by default for offline-safe scans).
type Config struct {
	FreshPopular FreshPopularConfig
}

// Detector runs behavioral heuristics that don't depend on external IOC
// lists. Sub-detectors emit findings tagged with detector "heuristic:<kind>".
type Detector struct {
	cfg Config
}

func New(cfg Config) *Detector { return &Detector{cfg: cfg} }

// Detect runs every sub-detector against the inventory and the scan tree.
func (d *Detector) Detect(ctx context.Context, inv *inventory.Inventory, scanRoot string) ([]findings.Finding, error) {
	_ = ctx
	var out []findings.Finding
	out = append(out, detectUnpinnedRefs(inv)...)
	out = append(out, detectCIShellPatterns(inv)...)
	out = append(out, detectInstallScripts(inv, scanRoot)...)
	out = append(out, detectTyposquats(inv)...)
	out = append(out, detectDepConfusion(inv, scanRoot)...)
	out = append(out, detectFreshPopular(inv, d.cfg.FreshPopular)...)
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
