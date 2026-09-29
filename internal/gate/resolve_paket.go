package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// ResolvePaketTree inspects the existing paket.lock; it does not resolve pending
// dependency changes. Paket does not include integrity hashes in this lockfile.
func ResolvePaketTree(ctx context.Context, paketPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("paket resolver requires the user's project cwd")
	}
	data, err := os.ReadFile(filepath.Join(cwd, "paket.lock"))
	if err != nil {
		return nil, fmt.Errorf("read paket.lock: %w", err)
	}
	packages, err := inventory.ParsePaketLockData(data)
	if err != nil {
		return nil, fmt.Errorf("parse paket.lock: %w", err)
	}
	if len(packages) == 0 {
		return nil, errors.New("paket.lock contains no inspectable NuGet packages")
	}
	refs := make([]PackageRef, 0, len(packages))
	for _, p := range packages {
		refs = append(refs, PackageRef{Ecosystem: "nuget", Name: p.Name, Version: p.Version})
	}
	return refs, nil
}
