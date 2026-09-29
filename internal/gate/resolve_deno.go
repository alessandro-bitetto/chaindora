package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// ResolveDenoTree resolves existing project dependencies using Deno 2. It does
// not model arbitrary new add/cache arguments. npm identities in lock versions
// 3-5 are supported; raw HTTPS/JSR imports remain outside registry coverage.
// Resolution uses a private cache, no node_modules, and no lifecycle scripts.
func ResolveDenoTree(ctx context.Context, denoPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("deno resolver requires the user's project cwd")
	}
	if denoPath == "" {
		denoPath = "deno"
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-deno-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)
	for _, name := range []string{"deno.json", "deno.jsonc", "package.json", "deno.lock"} {
		data, err := os.ReadFile(filepath.Join(cwd, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(tmp, name), data, 0o600); err != nil {
			return nil, err
		}
	}
	// Deno only runs npm lifecycle scripts when a node_modules directory is
	// enabled. Force none, including when the project config allows scripts.
	cmd := exec.CommandContext(ctx, denoPath, "install", "--lock=deno.lock", "--node-modules-dir=none")
	cmd.Dir = tmp
	cmd.Env = append(os.Environ(), "DENO_DIR="+filepath.Join(tmp, ".deno"), "DENO_NO_PROMPT=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, wrapPMError("deno", "install --node-modules-dir=none", out, err)
	}
	data, err := os.ReadFile(filepath.Join(tmp, "deno.lock"))
	if err != nil {
		return nil, fmt.Errorf("read generated deno.lock: %w", err)
	}
	packages, err := inventory.ParseDenoLockData(data)
	if err != nil {
		return nil, fmt.Errorf("parse deno.lock: %w", err)
	}
	if len(packages) == 0 {
		return nil, errors.New("deno.lock contains no inspectable npm packages")
	}
	refs := make([]PackageRef, 0, len(packages))
	for _, p := range packages {
		refs = append(refs, PackageRef{Ecosystem: "npm", Name: p.Name, Version: p.Version, Integrity: p.Integrity})
	}
	return refs, nil
}
