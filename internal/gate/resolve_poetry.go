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

// ResolvePoetryTree resolves what `poetry add <pkg>` would install.
// Approach:
//   1. tmpdir with a stub pyproject.toml in Poetry's
//      [tool.poetry] schema declaring the requested deps.
//   2. `poetry lock --no-update --no-interaction` resolves +
//      writes poetry.lock.
//   3. Parse poetry.lock TOML (table-format with [[package]] arrays).
//
// poetryPath is the absolute path to the real poetry binary so
// the gate's own shim doesn't loop.
func ResolvePoetryTree(ctx context.Context, poetryPath string, addArgs []string) ([]PackageRef, error) {
	if len(addArgs) == 0 {
		return nil, errors.New("no poetry add args supplied")
	}
	poetry := poetryPath
	if poetry == "" {
		poetry = "poetry"
	}
	pkgs, err := parsePoetryAddArgs(addArgs)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-poetry-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	var b strings.Builder
	b.WriteString(`[tool.poetry]
name = "chdora-gate-resolve"
version = "0.0.0"
description = ""
authors = []
package-mode = false

[tool.poetry.dependencies]
python = "^3.8"
`)
	for _, p := range pkgs {
		v := p.version
		if v == "" {
			v = "*"
		}
		fmt.Fprintf(&b, "%s = \"%s\"\n", p.name, v)
	}
	b.WriteString(`
[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
`)
	if err := os.WriteFile(filepath.Join(tmp, "pyproject.toml"), []byte(b.String()), 0o644); err != nil {
		return nil, err
	}

	// `poetry lock --no-update` works on Poetry 1.x. Poetry 2.x
	// renamed it to plain `poetry lock` (and made --no-update a
	// no-op). Try 1.x form first; on flag-rejection (exit 2)
	// fall through to the 2.x form.
	cmd := exec.CommandContext(ctx, poetry, "lock", "--no-update", "--no-interaction")
	cmd.Dir = tmp
	out, err := cmd.CombinedOutput()
	if err != nil {
		cmd = exec.CommandContext(ctx, poetry, "lock", "--no-interaction")
		cmd.Dir = tmp
		out2, err2 := cmd.CombinedOutput()
		if err2 != nil {
			return nil, wrapPMError("poetry", "lock", append(out, out2...), err2)
		}
	}
	data, err := os.ReadFile(filepath.Join(tmp, "poetry.lock"))
	if err != nil {
		return nil, fmt.Errorf("read poetry.lock: %w", err)
	}
	return parsePoetryLockTree(data, pkgs), nil
}

type poetryDepArg struct {
	name    string
	version string
}

// parsePoetryAddArgs accepts the forms `poetry add` understands:
//
//	requests                  → name=requests, version=*
//	requests@^2.31            → name=requests, version=^2.31
//	requests==2.31.0          → name=requests, version=2.31.0
//	django>=4.2,<5.0          → name=django, version=>=4.2,<5.0
//
// Flags are skipped.
func parsePoetryAddArgs(args []string) ([]poetryDepArg, error) {
	var out []poetryDepArg
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		dep := poetryDepArg{name: a}
		if i := strings.IndexAny(a, "@~^<>=!"); i > 0 {
			dep.name = a[:i]
			dep.version = a[i:]
			// Strip leading '@' since pyproject TOML wants raw
			// version constraint (e.g. "^2.0", not "@^2.0").
			dep.version = strings.TrimPrefix(dep.version, "@")
		}
		out = append(out, dep)
	}
	if len(out) == 0 {
		return nil, errors.New("no resolvable poetry packages in args")
	}
	return out, nil
}

// parsePoetryLockTree walks poetry.lock (TOML). Each [[package]]
// block has:
//
//	[[package]]
//	name = "requests"
//	version = "2.31.0"
//	files = [
//	    {file = "requests-2.31.0.tar.gz", hash = "sha256:abc..."},
//	    ...
//	]
//
// We use the first sha256 we find as PackageRef.Integrity.
func parsePoetryLockTree(data []byte, directs []poetryDepArg) []PackageRef {
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
		integrity := poetryLockFirstSha256(block)
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

// poetryLockField extracts `key = "value"` from a [[package]]
// block, stopping at the first nested table header.
func poetryLockField(block, key string) string {
	for _, line := range strings.Split(block, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			break
		}
		if !strings.HasPrefix(t, key+" = ") && !strings.HasPrefix(t, key+"=") {
			continue
		}
		eq := strings.Index(t, "=")
		v := strings.TrimSpace(t[eq+1:])
		return strings.Trim(v, `"`)
	}
	return ""
}

// poetryLockFirstSha256 finds the first hash = "sha256:..." entry
// in the package's files array. Used as Integrity.
func poetryLockFirstSha256(block string) string {
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
