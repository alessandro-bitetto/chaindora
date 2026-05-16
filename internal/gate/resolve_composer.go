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

// ResolveComposerTree resolves what `composer require <pkg>` would
// install. Approach:
//   1. tmpdir with a stub composer.json declaring the requested deps.
//   2. `composer update --no-install --no-scripts --no-plugins`
//      resolves + writes composer.lock without copying source files.
//   3. Parse composer.lock — every package has `dist.shasum` (sha1
//      of the zip) which we use as PackageRef.Integrity.
//
// --no-scripts + --no-plugins is critical: Composer plugins and
// pre/post-install scripts are exactly the payload class chdora
// is trying to refuse. We must not execute them during resolution.
//
// composerPath is the absolute path to the real composer binary.
func ResolveComposerTree(ctx context.Context, composerPath string, requireArgs []string) ([]PackageRef, error) {
	if len(requireArgs) == 0 {
		return nil, errors.New("no composer require args supplied")
	}
	composer := composerPath
	if composer == "" {
		composer = "composer"
	}
	pkgs, err := parseComposerRequireArgs(requireArgs)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-composer-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	stub := map[string]any{
		"name":              "chdora/gate-resolve",
		"description":       "chdora gate resolution stub",
		"minimum-stability": "stable",
		"require":           map[string]string{},
	}
	req := stub["require"].(map[string]string)
	for _, p := range pkgs {
		v := p.version
		if v == "" {
			v = "*"
		}
		req[p.name] = v
	}
	data, _ := json.MarshalIndent(stub, "", "  ")
	if err := os.WriteFile(filepath.Join(tmp, "composer.json"), data, 0o644); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, composer,
		"update",
		"--no-install",
		"--no-scripts",
		"--no-plugins",
		"--no-interaction",
		"--no-progress",
		"--quiet",
	)
	cmd.Dir = tmp
	// Isolate composer's cache so we don't pollute the user's
	// global ~/.composer/cache during resolution.
	cmd.Env = append(os.Environ(),
		"COMPOSER_HOME="+filepath.Join(tmp, "composer-home"),
		"COMPOSER_CACHE_DIR="+filepath.Join(tmp, "composer-cache"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapPMError("composer", "update --no-install", out, err)
	}
	lockData, err := os.ReadFile(filepath.Join(tmp, "composer.lock"))
	if err != nil {
		return nil, fmt.Errorf("read composer.lock: %w", err)
	}
	return parseComposerLockTree(lockData, pkgs)
}

type composerReqArg struct {
	name    string
	version string
}

// parseComposerRequireArgs accepts composer require's syntax:
//
//	vendor/pkg            → name=vendor/pkg, version=*
//	vendor/pkg:^1.0       → name=vendor/pkg, version=^1.0   (canonical)
//	vendor/pkg@^1.0       → same                            (shorthand)
//
// Flags are skipped.
func parseComposerRequireArgs(args []string) ([]composerReqArg, error) {
	var out []composerReqArg
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		dep := composerReqArg{name: a}
		// Prefer ':' (canonical composer) over '@' since some
		// composer package names contain '@' in suffixes (rare,
		// but the colon form is unambiguous).
		if i := strings.LastIndex(a, ":"); i > 0 {
			dep.name = a[:i]
			dep.version = a[i+1:]
		} else if i := strings.LastIndex(a, "@"); i > 0 {
			dep.name = a[:i]
			dep.version = a[i+1:]
		}
		out = append(out, dep)
	}
	if len(out) == 0 {
		return nil, errors.New("no resolvable composer packages in args")
	}
	return out, nil
}

func parseComposerLockTree(data []byte, directs []composerReqArg) ([]PackageRef, error) {
	var lock struct {
		Packages    []composerPackageEntry `json:"packages"`
		PackagesDev []composerPackageEntry `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}
	directNames := map[string]struct{}{}
	for _, d := range directs {
		directNames[d.name] = struct{}{}
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	all := append(lock.Packages, lock.PackagesDev...)
	for _, p := range all {
		if p.Name == "" || p.Version == "" {
			continue
		}
		key := p.Name + "@" + p.Version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if p.Dist.Shasum != "" {
			integrity = "sha1:" + p.Dist.Shasum
		}
		_, isDirect := directNames[p.Name]
		refs = append(refs, PackageRef{
			Ecosystem: "packagist",
			Name:      p.Name,
			Version:   p.Version,
			Direct:    isDirect,
			Integrity: integrity,
		})
	}
	return refs, nil
}

type composerPackageEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Type   string `json:"type"`
		Shasum string `json:"shasum"`
	} `json:"dist"`
}
