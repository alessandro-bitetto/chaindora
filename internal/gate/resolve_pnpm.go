package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ResolvePnpmTree returns every (pkg, version) that
// `pnpm add <pkgs>` would land on disk. pnpm's lockfile
// (pnpm-lock.yaml) is YAML-native, which makes parsing more
// reliable than yarn classic.
//
// Like the other resolvers: run pnpm in a tmpdir with scripts
// disabled and `--lockfile-only` so it writes the lockfile
// without actually installing.
func ResolvePnpmTree(ctx context.Context, pnpmPath string, addArgs []string) ([]PackageRef, error) {
	if len(addArgs) == 0 {
		return nil, errors.New("no add args supplied")
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-pnpm-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	pkgJSON := `{"name":"chdora-gate-resolve","version":"0.0.0","private":true}`
	if err := os.WriteFile(filepath.Join(tmp, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		return nil, fmt.Errorf("seed package.json: %w", err)
	}

	pnpm := pnpmPath
	if pnpm == "" {
		pnpm = "pnpm"
	}
	cleaned := stripPnpmNetFlags(addArgs)
	args := append([]string{
		"add",
		"--lockfile-only",
		"--ignore-scripts",
		"--reporter=silent",
	}, cleaned...)
	cmd := exec.CommandContext(ctx, pnpm, args...)
	cmd.Dir = tmp
	if out, err := cmd.CombinedOutput(); err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 400 {
			snippet = snippet[:400] + "..."
		}
		return nil, fmt.Errorf("pnpm add --lockfile-only failed: %w\n%s", err, snippet)
	}
	return parsePnpmLock(tmp, addArgs)
}

// parsePnpmLock walks pnpm-lock.yaml and extracts every
// resolved (name, version) tuple. pnpm's lockfile groups
// packages under a top-level `packages:` map keyed by
// `/<name>@<version>` or `/<scope>/<name>@<version>`.
func parsePnpmLock(dir string, addArgs []string) ([]PackageRef, error) {
	data, err := os.ReadFile(filepath.Join(dir, "pnpm-lock.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read pnpm-lock.yaml: %w", err)
	}
	var lock struct {
		Packages map[string]struct {
			Version string `yaml:"version"`
		} `yaml:"packages"`
		// Newer pnpm uses `snapshots:` keyed similarly.
		Snapshots map[string]any `yaml:"snapshots,omitempty"`
	}
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse pnpm-lock.yaml: %w", err)
	}
	directs := directNamesFromArgs(addArgs)
	seen := map[string]struct{}{}
	var refs []PackageRef
	for key, entry := range lock.Packages {
		name, version := parsePnpmKey(key)
		// Some pnpm formats put the version in the value, not
		// the key (e.g. `/pkg@`). Fall back to entry.Version.
		if version == "" {
			version = entry.Version
		}
		if name == "" || version == "" {
			continue
		}
		ident := name + "@" + version
		if _, dup := seen[ident]; dup {
			continue
		}
		seen[ident] = struct{}{}
		refs = append(refs, PackageRef{
			Ecosystem: "npm",
			Name:      name,
			Version:   version,
			Direct:    directs[name],
		})
	}
	return refs, nil
}

// parsePnpmKey splits a pnpm lockfile key into (name, version).
// Handles the three forms pnpm has used across versions:
//
//	"/lodash/4.17.21"               (pnpm v5-6)
//	"/lodash@4.17.21"               (pnpm v7+)
//	"/@scope/pkg/1.0.0"             (pnpm v5-6 scoped)
//	"/@scope/pkg@1.0.0"             (pnpm v7+ scoped)
//	"lodash@4.17.21"                (no leading slash, rare)
func parsePnpmKey(key string) (name, version string) {
	k := strings.TrimPrefix(key, "/")
	// Strip pnpm-v7's "(peerDeps)" / " " annotations FIRST so
	// the subsequent '@' search doesn't find an `@` inside the
	// peerdep clause. "/foo@1.2.3 (react@18)" → "/foo@1.2.3".
	if i := strings.IndexAny(k, " ("); i >= 0 {
		k = k[:i]
	}
	// v7+ form: <name>@<version>, where name may contain '/'
	// for scoped packages. The version separator is the LAST
	// '@' that isn't the leading scope @.
	atIdx := -1
	if strings.HasPrefix(k, "@") {
		if i := strings.LastIndex(k[1:], "@"); i > 0 {
			atIdx = i + 1
		}
	} else {
		atIdx = strings.LastIndex(k, "@")
	}
	if atIdx > 0 {
		name = k[:atIdx]
		version = k[atIdx+1:]
		return name, version
	}
	// v5-6 fallback: last '/' separates name from version.
	if i := strings.LastIndex(k, "/"); i > 0 {
		return k[:i], k[i+1:]
	}
	return "", ""
}

// ResolvePnpmUpdateAll resolves what `pnpm update` (no args) would
// land on disk. Same pattern as ResolveNPMUpdateAll: copy the user's
// package.json + pnpm-lock.yaml into a temp dir and run pnpm in
// lockfile-only mode there.
func ResolvePnpmUpdateAll(ctx context.Context, pnpmPath, cwd string) ([]PackageRef, error) {
	pjPath := filepath.Join(cwd, "package.json")
	pjBytes, err := os.ReadFile(pjPath)
	if err != nil {
		return nil, fmt.Errorf("read package.json in %s: %w", cwd, err)
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-pnpm-update-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	if err := os.WriteFile(filepath.Join(tmp, "package.json"), pjBytes, 0o644); err != nil {
		return nil, fmt.Errorf("seed package.json: %w", err)
	}
	if lockBytes, err := os.ReadFile(filepath.Join(cwd, "pnpm-lock.yaml")); err == nil {
		if err := os.WriteFile(filepath.Join(tmp, "pnpm-lock.yaml"), lockBytes, 0o644); err != nil {
			return nil, fmt.Errorf("seed pnpm-lock.yaml: %w", err)
		}
	}

	pnpm := pnpmPath
	if pnpm == "" {
		pnpm = "pnpm"
	}
	cmd := exec.CommandContext(ctx, pnpm,
		"update",
		"--lockfile-only",
		"--ignore-scripts",
		"--reporter=silent",
	)
	cmd.Dir = tmp
	if out, err := cmd.CombinedOutput(); err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 400 {
			snippet = snippet[:400] + "..."
		}
		return nil, fmt.Errorf("pnpm update --lockfile-only failed: %w\n%s", err, snippet)
	}
	// Reuse the standard parser; pass no addArgs so directs comes
	// from the pnpm lockfile structure itself (top-level importers).
	return parsePnpmLock(tmp, nil)
}

func stripPnpmNetFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		switch a {
		case "--dry-run", "-n":
			continue
		}
		out = append(out, a)
	}
	return out
}
