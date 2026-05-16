package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ResolveBunTree resolves what `bun add <pkg>` would install
// (direct + transitive). Bun uses an npm-compatible registry, so
// PackageRefs are emitted with Ecosystem="npm" — the OSV checker,
// cooldown probe, publisher-change probe, etc. all reuse the
// existing npm infrastructure.
//
// Bun's lockfile (bun.lockb) is binary — there's no first-class
// way to parse it without bun itself. Approach:
//  1. tmpdir with stub package.json.
//  2. `bun install <pkgs> --ignore-scripts --backend=copyfile`
//     resolves + downloads .tgz bytes into temp node_modules.
//     --ignore-scripts is critical: bun runs preinstall/postinstall
//     by default, exactly the payload class we're trying to gate.
//  3. `bun pm ls --json` walks the resolved tree and prints JSON
//     with name, version, and integrity per node.
//
// bunPath is the absolute path to the real `bun` binary so the
// shim doesn't loop.
func ResolveBunTree(ctx context.Context, bunPath string, addArgs []string) ([]PackageRef, error) {
	if len(addArgs) == 0 {
		return nil, errors.New("no bun add args supplied")
	}
	bun := bunPath
	if bun == "" {
		bun = "bun"
	}
	// Strip a leading "add" / "install" verb token that survived
	// classifyGateArgs.
	if len(addArgs) > 0 && (addArgs[0] == "add" || addArgs[0] == "install" || addArgs[0] == "i") {
		addArgs = addArgs[1:]
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-bun-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	pkgJSON := `{"name":"chdora-gate-resolve","version":"0.0.0","private":true}`
	if err := os.WriteFile(filepath.Join(tmp, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		return nil, fmt.Errorf("seed package.json: %w", err)
	}

	args := append([]string{
		"install",
		"--ignore-scripts",
		"--backend=copyfile",
		"--no-save",
	}, addArgs...)
	cmd := exec.CommandContext(ctx, bun, args...)
	cmd.Dir = tmp
	cmd.Env = append(os.Environ(), "BUN_INSTALL_CACHE_DIR="+filepath.Join(tmp, ".bun-cache"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapPMError("bun", "install --ignore-scripts", out, err)
	}

	// Now enumerate. `bun pm ls --json` outputs a tree of objects.
	enumCmd := exec.CommandContext(ctx, bun, "pm", "ls", "--all")
	enumCmd.Dir = tmp
	listOut, err := enumCmd.CombinedOutput()
	if err != nil {
		return nil, wrapPMError("bun", "pm ls --all", listOut, err)
	}
	directs := directNamesFromArgs(addArgs)
	return parseBunPmLs(listOut, directs), nil
}

// parseBunPmLs parses `bun pm ls --all` output. As of bun 1.x, the
// output is a plain-text tree, one entry per line:
//
//	chdora-gate-resolve@0.0.0 /tmp/...
//	├── lodash@4.17.21
//	└── chalk@5.3.0
//
// We extract <name>@<version> tokens. Integrity isn't surfaced by
// `bun pm ls` directly — we'll get it from npm's own registry
// probes downstream via the existing cooldown/publisher checkers.
// For now, leave Integrity empty for bun-resolved packages; the
// republish-guard won't fire for bun specifically until bun
// exposes integrity. This is the same trade-off Gradle makes.
func parseBunPmLs(out []byte, directs map[string]bool) []PackageRef {
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, line := range strings.Split(string(out), "\n") {
		// Trim tree-drawing chars and whitespace.
		trimmed := strings.TrimLeft(line, "├─└│ \t")
		if trimmed == "" || strings.Contains(trimmed, " ") && !strings.Contains(trimmed, "@") {
			continue
		}
		// Token shape: name@version or @scope/name@version.
		atIdx := -1
		if strings.HasPrefix(trimmed, "@") {
			if i := strings.LastIndex(trimmed[1:], "@"); i > 0 {
				atIdx = i + 1
			}
		} else {
			atIdx = strings.LastIndex(trimmed, "@")
		}
		if atIdx <= 0 {
			continue
		}
		// Stop at first whitespace in version (some bun versions
		// suffix the version with path or metadata).
		version := trimmed[atIdx+1:]
		if i := strings.IndexAny(version, " \t"); i >= 0 {
			version = version[:i]
		}
		name := trimmed[:atIdx]
		if name == "chdora-gate-resolve" || name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, PackageRef{
			Ecosystem: "npm",
			Name:      name,
			Version:   version,
			Direct:    directs[name],
		})
	}
	return refs
}

// bunInfo is unused today — placeholder for a future enrichment
// pass that fetches integrity from the npm registry directly,
// since bun pm ls doesn't surface it.
type bunInfo struct{ ignored json.RawMessage }
