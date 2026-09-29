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

// ResolveUVTree resolves what `uv add <pkg>` would install.
// Approach:
//   1. tmpdir with a minimal pyproject.toml in PEP 621 format
//      (uv uses [project] not [tool.poetry]).
//   2. `uv lock --no-progress` resolves + writes uv.lock.
//   3. Parse uv.lock TOML.
//
// uvPath is the absolute path to the real `uv` binary.
func ResolveUVTree(ctx context.Context, uvPath string, addArgs []string) ([]PackageRef, error) {
	if len(addArgs) == 0 {
		return nil, errors.New("no uv add args supplied")
	}
	uv := uvPath
	if uv == "" {
		uv = "uv"
	}
	pkgs, err := parseUVAddArgs(addArgs)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-uv-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	var b strings.Builder
	b.WriteString(`[project]
name = "chdora-gate-resolve"
version = "0.0.0"
requires-python = ">=3.8"
dependencies = [
`)
	for _, p := range pkgs {
		if p.constraint != "" {
			fmt.Fprintf(&b, "  \"%s%s\",\n", p.name, p.constraint)
		} else {
			fmt.Fprintf(&b, "  \"%s\",\n", p.name)
		}
	}
	b.WriteString("]\n")
	if err := os.WriteFile(filepath.Join(tmp, "pyproject.toml"), []byte(b.String()), 0o644); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, uv, "lock", "--no-progress")
	cmd.Dir = tmp
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapPMError("uv", "lock", out, err)
	}
	data, err := os.ReadFile(filepath.Join(tmp, "uv.lock"))
	if err != nil {
		return nil, fmt.Errorf("read uv.lock: %w", err)
	}
	return parseUVLockTree(data, pkgs), nil
}

type uvDepArg struct {
	name       string
	constraint string
}

// parseUVAddArgs accepts uv add's syntax — PEP 508 dependency
// specifiers:
//
//	requests             → name=requests
//	requests==2.31.0     → name=requests, constraint===2.31.0
//	django>=4.2          → name=django, constraint=>=4.2
//	flask@^3.0           → name=flask, constraint=@^3.0
//
// Flags are skipped.
func parseUVAddArgs(args []string) ([]uvDepArg, error) {
	var out []uvDepArg
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		dep := uvDepArg{name: a}
		if i := strings.IndexAny(a, "@~^<>=!"); i > 0 {
			dep.name = a[:i]
			dep.constraint = a[i:]
		}
		out = append(out, dep)
	}
	if len(out) == 0 {
		return nil, errors.New("no resolvable uv packages in args")
	}
	return out, nil
}

// parseUVLockTree walks uv.lock (TOML). Each [[package]] block
// has name, version, and a sdist + wheels list with sha256
// hashes. We use the first sha256 found.
func parseUVLockTree(data []byte, directs []uvDepArg) []PackageRef {
	directNames := map[string]struct{}{}
	for _, d := range directs {
		directNames[normalizePyPIName(d.name)] = struct{}{}
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, block := range strings.Split(string(data), "[[package]]")[1:] {
		name := poetryLockField(block, "name")
		version := poetryLockField(block, "version")
		if name == "" || version == "" {
			continue
		}
		canonical := normalizePyPIName(name)
		key := canonical + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := uvLockFirstSha256(block)
		_, isDirect := directNames[canonical]
		refs = append(refs, PackageRef{
			Ecosystem: "pypi",
			Name:      canonical,
			Version:   version,
			Direct:    isDirect,
			Integrity: integrity,
		})
	}
	return refs
}

// uvLockFirstSha256 finds the first `hash = "sha256:..."` field
// in a [[package]] block. uv.lock uses inline tables for sdist
// and per-wheel entries, both with sha256.
func uvLockFirstSha256(block string) string {
	idx := strings.Index(block, `hash = "sha256:`)
	if idx < 0 {
		return ""
	}
	v := block[idx+len(`hash = "`):]
	if end := strings.Index(v, `"`); end >= 0 {
		return v[:end]
	}
	return ""
}
