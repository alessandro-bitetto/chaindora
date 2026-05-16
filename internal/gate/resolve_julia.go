package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveJuliaTree parses Julia's Manifest.toml, the resolved
// dependency state for a Project.toml. Each [[deps]] block has
// uuid, name, version, and git-tree-sha1 which we use as
// Integrity.
//
// Julia's Pkg interface is REPL-driven (`using Pkg; Pkg.add(...)`)
// so there's no clean CLI invocation to gate. Instead the gate
// operates against the user's cwd, parsing Manifest.toml directly.
//
// juliaPath unused; kept for signature parity.
func ResolveJuliaTree(ctx context.Context, juliaPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("julia resolver requires the user's project cwd")
	}
	data, err := os.ReadFile(filepath.Join(cwd, "Manifest.toml"))
	if err != nil {
		return nil, fmt.Errorf("read Manifest.toml: %w", err)
	}
	return parseJuliaManifest(data), nil
}

// parseJuliaManifest extracts (name, version, git-tree-sha1) from
// a Manifest.toml. Format:
//
//	[[deps.DataFrames]]
//	uuid = "..."
//	version = "1.6.1"
//	git-tree-sha1 = "abc..."
//
// Manifest v1 used [[NAME]] without the deps. prefix. We handle both.
func parseJuliaManifest(data []byte) []PackageRef {
	seen := map[string]struct{}{}
	var refs []PackageRef
	// Split on top-level [[ headers. The chunk before the next [[
	// belongs to one entry.
	chunks := strings.Split(string(data), "[[")
	for _, c := range chunks[1:] {
		// First line is the entry name: "deps.NAME]]" or "NAME]]".
		end := strings.Index(c, "]]")
		if end <= 0 {
			continue
		}
		header := c[:end]
		body := c[end+2:]
		name := strings.TrimPrefix(header, "deps.")
		// Stop at next section header in body.
		if i := strings.Index(body, "\n["); i >= 0 {
			body = body[:i]
		}
		version := tomlScalar(body, "version")
		sha := tomlScalar(body, "git-tree-sha1")
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if sha != "" {
			integrity = "git-tree-sha1:" + sha
		}
		refs = append(refs, PackageRef{
			Ecosystem: "julia",
			Name:      name,
			Version:   version,
			Integrity: integrity,
		})
	}
	return refs
}

// tomlScalar extracts a `key = "value"` field from a TOML block.
func tomlScalar(block, key string) string {
	for _, line := range strings.Split(block, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, key+" = ") && !strings.HasPrefix(t, key+"=") {
			continue
		}
		eq := strings.Index(t, "=")
		v := strings.TrimSpace(t[eq+1:])
		return strings.Trim(v, `"`)
	}
	return ""
}
