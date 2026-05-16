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

// ResolvePDMTree resolves what `pdm add <pkg>` would install.
// Same shape as Poetry: stub pyproject.toml + `pdm lock`.
// pdm.lock is TOML with [[package]] blocks and per-file hashes.
func ResolvePDMTree(ctx context.Context, pdmPath string, addArgs []string) ([]PackageRef, error) {
	if len(addArgs) == 0 {
		return nil, errors.New("no pdm add args supplied")
	}
	pdm := pdmPath
	if pdm == "" {
		pdm = "pdm"
	}
	if addArgs[0] == "add" {
		addArgs = addArgs[1:]
	}
	pkgs, err := parsePDMAddArgs(addArgs)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-pdm-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)
	var b strings.Builder
	b.WriteString("[project]\nname = \"chdora-gate-resolve\"\nversion = \"0.0.0\"\nrequires-python = \">=3.8\"\ndependencies = [\n")
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
	cmd := exec.CommandContext(ctx, pdm, "lock", "--no-cross-platform")
	cmd.Dir = tmp
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapPMError("pdm", "lock", out, err)
	}
	data, err := os.ReadFile(filepath.Join(tmp, "pdm.lock"))
	if err != nil {
		return nil, fmt.Errorf("read pdm.lock: %w", err)
	}
	return parsePDMLockTree(data, pkgs), nil
}

type pdmDepArg struct {
	name       string
	constraint string
}

func parsePDMAddArgs(args []string) ([]pdmDepArg, error) {
	var out []pdmDepArg
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		dep := pdmDepArg{name: a}
		if i := strings.IndexAny(a, "@~^<>=!"); i > 0 {
			dep.name = a[:i]
			dep.constraint = strings.TrimPrefix(a[i:], "@")
		}
		out = append(out, dep)
	}
	if len(out) == 0 {
		return nil, errors.New("no resolvable pdm packages")
	}
	return out, nil
}

// parsePDMLockTree parses pdm.lock — TOML with [[package]] blocks
// similar to poetry.lock; per-file hashes under `files` array.
func parsePDMLockTree(data []byte, directs []pdmDepArg) []PackageRef {
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
