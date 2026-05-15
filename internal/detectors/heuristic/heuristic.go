package heuristic

import (
	"context"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// Detector runs behavioral heuristics that don't depend on external IOC
// lists. Sub-detectors emit findings tagged with detector "heuristic:<kind>".
type Detector struct{}

func New() *Detector { return &Detector{} }

// Detect runs every sub-detector against the inventory and the scan tree.
func (d *Detector) Detect(ctx context.Context, inv *inventory.Inventory, scanRoot string) ([]findings.Finding, error) {
	_ = ctx
	var out []findings.Finding
	out = append(out, detectUnpinnedRefs(inv)...)
	out = append(out, detectCIShellPatterns(inv)...)
	out = append(out, detectInstallScripts(inv, scanRoot)...)
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
