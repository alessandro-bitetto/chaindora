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

// ResolvePipenvTree resolves what `pipenv install <pkg>` would
// install. Approach:
//   1. tmpdir with stub Pipfile.
//   2. `pipenv lock --keep-outdated` resolves + writes
//      Pipfile.lock with sha256 hashes.
//   3. Parse Pipfile.lock JSON.
//
// pipenvPath is the absolute path to the real `pipenv` binary.
func ResolvePipenvTree(ctx context.Context, pipenvPath string, installArgs []string) ([]PackageRef, error) {
	if len(installArgs) == 0 {
		return nil, errors.New("no pipenv install args supplied")
	}
	pipenv := pipenvPath
	if pipenv == "" {
		pipenv = "pipenv"
	}
	// Strip a leading "install" verb.
	if installArgs[0] == "install" {
		installArgs = installArgs[1:]
	}
	pkgs, err := parsePipenvInstallArgs(installArgs)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-pipenv-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	var b strings.Builder
	b.WriteString("[[source]]\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\nname = \"pypi\"\n\n[packages]\n")
	for _, p := range pkgs {
		v := p.constraint
		if v == "" {
			v = "*"
		}
		fmt.Fprintf(&b, "%s = \"%s\"\n", p.name, v)
	}
	if err := os.WriteFile(filepath.Join(tmp, "Pipfile"), []byte(b.String()), 0o644); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, pipenv, "lock")
	cmd.Dir = tmp
	cmd.Env = append(os.Environ(),
		"PIPENV_VENV_IN_PROJECT=0",
		"PIPENV_NOSPIN=1",
		"PIPENV_NO_INHERIT=1",
		"PIPENV_IGNORE_VIRTUALENVS=1",
		"WORKON_HOME="+filepath.Join(tmp, "venvs"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapPMError("pipenv", "lock", out, err)
	}
	data, err := os.ReadFile(filepath.Join(tmp, "Pipfile.lock"))
	if err != nil {
		return nil, fmt.Errorf("read Pipfile.lock: %w", err)
	}
	return parsePipfileLockTree(data, pkgs)
}

type pipenvDepArg struct {
	name       string
	constraint string
}

func parsePipenvInstallArgs(args []string) ([]pipenvDepArg, error) {
	var out []pipenvDepArg
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		dep := pipenvDepArg{name: a}
		if i := strings.IndexAny(a, "@~^<>=!"); i > 0 {
			dep.name = a[:i]
			dep.constraint = strings.TrimPrefix(a[i:], "@")
		}
		out = append(out, dep)
	}
	if len(out) == 0 {
		return nil, errors.New("no resolvable pipenv packages")
	}
	return out, nil
}

// parsePipfileLockTree walks Pipfile.lock JSON. Schema:
//
//	{
//	  "_meta": {...},
//	  "default": {
//	    "requests": {
//	      "version": "==2.31.0",
//	      "hashes": ["sha256:abc...", "sha256:def..."]
//	    }
//	  },
//	  "develop": {...}
//	}
func parsePipfileLockTree(data []byte, directs []pipenvDepArg) ([]PackageRef, error) {
	var lock struct {
		Default map[string]struct {
			Version string   `json:"version"`
			Hashes  []string `json:"hashes"`
		} `json:"default"`
		Develop map[string]struct {
			Version string   `json:"version"`
			Hashes  []string `json:"hashes"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse Pipfile.lock: %w", err)
	}
	directNames := map[string]struct{}{}
	for _, d := range directs {
		directNames[normalizePyPIName(d.name)] = struct{}{}
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, group := range []map[string]struct {
		Version string   `json:"version"`
		Hashes  []string `json:"hashes"`
	}{lock.Default, lock.Develop} {
		for name, entry := range group {
			version := strings.TrimPrefix(entry.Version, "==")
			canonical := normalizePyPIName(name)
			if canonical == "" || version == "" {
				continue
			}
			key := canonical + "@" + version
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			integrity := ""
			if len(entry.Hashes) > 0 {
				integrity = entry.Hashes[0]
			}
			_, isDirect := directNames[canonical]
			refs = append(refs, PackageRef{
				Ecosystem: "pypi",
				Name:      canonical,
				Version:   version,
				Direct:    isDirect,
				Integrity: integrity,
			})
		}
	}
	return refs, nil
}
