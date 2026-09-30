package cli

import (
	"context"
	"path/filepath"

	"github.com/alessandro-bitetto/chaindora/internal/detectors/integrity"
	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

func installedIntegrity(ctx context.Context, inv *inventory.Inventory, offline bool) []findings.Finding {
	d := integrity.New(nil)
	d.Offline = offline
	var out []findings.Finding
	seen := map[string]bool{}
	for _, source := range inv.Sources {
		if filepath.Base(source.Path) == "package-lock.json" && !seen[source.Path] {
			seen[source.Path] = true
			out = append(out, d.VerifyNPMLock(ctx, source.Path)...)
		}
	}
	return out
}
