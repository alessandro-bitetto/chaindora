package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ResolveCargoTree resolves what `cargo add` would install,
// without compiling anything. Approach:
//   1. Make a tmpdir with a minimal Cargo.toml that declares
//      the user's packages as deps + an empty src/lib.rs.
//   2. Run `cargo generate-lockfile` (offline-fetches the
//      registry index and resolves) — this writes Cargo.lock.
//   3. Parse the Cargo.lock TOML.
//
// We use generate-lockfile (rather than `cargo fetch`) because
// it doesn't download .crate files — registry index only — so
// the resolution step itself can't trigger build scripts.
//
// cargoPath is the absolute path to the real cargo binary so
// the gate's own shim doesn't loop.
func ResolveCargoTree(ctx context.Context, cargoPath string, addArgs []string) ([]PackageRef, error) {
	if len(addArgs) == 0 {
		return nil, errors.New("no cargo add args supplied")
	}
	cargo := cargoPath
	if cargo == "" {
		cargo = "cargo"
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-cargo-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	// Build a minimal Cargo.toml with the requested deps.
	deps, err := parseCargoAddArgs(addArgs)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(tmp, "src"), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(tmp, "src", "lib.rs"), nil, 0o644); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("[package]\nname = \"chdora-gate-resolve\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\n")
	for _, d := range deps {
		if d.version != "" {
			fmt.Fprintf(&b, "%s = \"%s\"\n", d.name, d.version)
		} else {
			fmt.Fprintf(&b, "%s = \"*\"\n", d.name)
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, "Cargo.toml"), []byte(b.String()), 0o644); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, cargo, "generate-lockfile")
	cmd.Dir = tmp
	if out, err := cmd.CombinedOutput(); err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 400 {
			snippet = snippet[:400] + "..."
		}
		return nil, fmt.Errorf("cargo generate-lockfile failed: %w\n%s", err, snippet)
	}

	data, err := os.ReadFile(filepath.Join(tmp, "Cargo.lock"))
	if err != nil {
		return nil, fmt.Errorf("read generated Cargo.lock: %w", err)
	}
	return parseCargoLockTree(data, deps), nil
}

type cargoDepArg struct {
	name    string
	version string // empty = any
}

// parseCargoAddArgs accepts forms cargo add supports:
//   "serde"            → name=serde, version=*
//   "serde@1.0"        → name=serde, version=1.0
//   "serde@^1.0.193"   → same
// Flags are skipped.
func parseCargoAddArgs(args []string) ([]cargoDepArg, error) {
	var deps []cargoDepArg
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		dep := cargoDepArg{name: a}
		if i := strings.Index(a, "@"); i > 0 {
			dep.name = a[:i]
			dep.version = a[i+1:]
		}
		deps = append(deps, dep)
	}
	if len(deps) == 0 {
		return nil, errors.New("no resolvable cargo packages in args")
	}
	return deps, nil
}

// parseCargoLockTree turns a Cargo.lock blob into PackageRefs.
// Marks direct=true for entries the user explicitly named in
// addArgs. Skips the synthetic chdora-gate-resolve crate.
func parseCargoLockTree(data []byte, directs []cargoDepArg) []PackageRef {
	directNames := map[string]struct{}{}
	for _, d := range directs {
		directNames[d.name] = struct{}{}
	}
	var refs []PackageRef
	seen := map[string]struct{}{}
	for _, b := range strings.Split(string(data), "[[package]]")[1:] {
		name := cargoLockField(b, "name")
		version := cargoLockField(b, "version")
		source := cargoLockField(b, "source")
		// Skip non-registry sources and our synthetic root.
		if name == "" || version == "" || name == "chdora-gate-resolve" {
			continue
		}
		if source != "" && !strings.Contains(source, "crates.io-index") {
			// Local path or git dep — not crates.io supply chain.
			// Future: route to git-URL evaluator.
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		_, isDirect := directNames[name]
		refs = append(refs, PackageRef{
			Ecosystem: "crates",
			Name:      name,
			Version:   version,
			Direct:    isDirect,
		})
	}
	return refs
}

func cargoLockField(block, key string) string {
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			break
		}
		if !strings.HasPrefix(trimmed, key+" = ") && !strings.HasPrefix(trimmed, key+"=") {
			continue
		}
		eq := strings.Index(trimmed, "=")
		v := strings.TrimSpace(trimmed[eq+1:])
		v = strings.Trim(v, `"`)
		return v
	}
	return ""
}
