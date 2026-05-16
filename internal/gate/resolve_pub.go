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

// ResolvePubTree resolves what `dart pub add <pkg>` (or
// `flutter pub add <pkg>`) would install. Approach:
//   1. tmpdir with a minimal pubspec.yaml declaring the
//      requested deps.
//   2. `dart pub get --offline=false --no-precompile` resolves
//      and writes pubspec.lock.
//   3. Parse pubspec.lock — every dependency has a sha256 in
//      its description.
//
// dartPath is the absolute path to the real `dart` (or `flutter`)
// binary so the gate's own shim doesn't loop.
func ResolvePubTree(ctx context.Context, dartPath string, addArgs []string) ([]PackageRef, error) {
	if len(addArgs) == 0 {
		return nil, errors.New("no dart pub add args supplied")
	}
	dart := dartPath
	if dart == "" {
		dart = "dart"
	}
	// Strip a leading "pub" / "add" token if present — `dart pub
	// add http` arrives as args=["pub", "add", "http"] after the
	// classifier hands us pmArgs[1:].
	cleaned := stripPubVerbTokens(addArgs)
	pkgs := parsePubAddArgs(cleaned)
	if len(pkgs) == 0 {
		return nil, errors.New("no resolvable pub packages in args")
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-pub-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	var b strings.Builder
	b.WriteString("name: chdora_gate_resolve\nversion: 0.0.0\nenvironment:\n  sdk: '>=2.17.0 <4.0.0'\ndependencies:\n")
	for _, p := range pkgs {
		v := p.constraint
		if v == "" {
			v = "any"
		}
		fmt.Fprintf(&b, "  %s: \"%s\"\n", p.name, v)
	}
	if err := os.WriteFile(filepath.Join(tmp, "pubspec.yaml"), []byte(b.String()), 0o644); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, dart, "pub", "get", "--no-precompile")
	cmd.Dir = tmp
	cmd.Env = append(os.Environ(), "PUB_CACHE="+filepath.Join(tmp, "pub-cache"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapPMError("dart", "pub get", out, err)
	}
	data, err := os.ReadFile(filepath.Join(tmp, "pubspec.lock"))
	if err != nil {
		return nil, fmt.Errorf("read pubspec.lock: %w", err)
	}
	return parsePubspecLockTree(data, pkgs), nil
}

// ResolvePubFromCwd handles `dart pub get` / `dart pub upgrade`
// invocations — the user already has a pubspec.yaml; we just run
// the resolver against it.
func ResolvePubFromCwd(ctx context.Context, dartPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("pub-from-cwd resolver requires the user's project cwd")
	}
	dart := dartPath
	if dart == "" {
		dart = "dart"
	}
	pubspec, err := os.ReadFile(filepath.Join(cwd, "pubspec.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read pubspec.yaml in %s: %w", cwd, err)
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-pub-cwd-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)
	if err := os.WriteFile(filepath.Join(tmp, "pubspec.yaml"), pubspec, 0o644); err != nil {
		return nil, fmt.Errorf("seed pubspec.yaml: %w", err)
	}
	cmd := exec.CommandContext(ctx, dart, "pub", "get", "--no-precompile")
	cmd.Dir = tmp
	cmd.Env = append(os.Environ(), "PUB_CACHE="+filepath.Join(tmp, "pub-cache"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapPMError("dart", "pub get (cwd)", out, err)
	}
	data, err := os.ReadFile(filepath.Join(tmp, "pubspec.lock"))
	if err != nil {
		return nil, fmt.Errorf("read pubspec.lock: %w", err)
	}
	return parsePubspecLockTree(data, nil), nil
}

type pubDepArg struct {
	name       string
	constraint string
}

func stripPubVerbTokens(args []string) []string {
	out := append([]string(nil), args...)
	for len(out) > 0 && (out[0] == "pub" || out[0] == "add") {
		out = out[1:]
	}
	return out
}

func parsePubAddArgs(args []string) []pubDepArg {
	var out []pubDepArg
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		dep := pubDepArg{name: a}
		if i := strings.Index(a, ":"); i > 0 {
			dep.name = a[:i]
			dep.constraint = a[i+1:]
		}
		out = append(out, dep)
	}
	return out
}

// parsePubspecLockTree parses pubspec.lock — YAML format with a
// `packages:` map keyed by package name. Each entry has
// description.{name, sha256, url} and version.
func parsePubspecLockTree(data []byte, directs []pubDepArg) []PackageRef {
	directNames := map[string]struct{}{}
	for _, d := range directs {
		directNames[d.name] = struct{}{}
	}
	var lock struct {
		Packages map[string]struct {
			Dependency  string `yaml:"dependency"`
			Description struct {
				Name   string `yaml:"name"`
				Sha256 string `yaml:"sha256"`
				URL    string `yaml:"url"`
			} `yaml:"description"`
			Source  string `yaml:"source"`
			Version string `yaml:"version"`
		} `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	for name, entry := range lock.Packages {
		if entry.Version == "" {
			continue
		}
		// Only gate hosted pub.dev sources for now — git / path
		// sources have their own threat model (covered by git-url
		// checker for git, untrusted for path).
		if entry.Source != "" && entry.Source != "hosted" {
			continue
		}
		realName := entry.Description.Name
		if realName == "" {
			realName = name
		}
		key := realName + "@" + entry.Version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if entry.Description.Sha256 != "" {
			integrity = "sha256:" + entry.Description.Sha256
		}
		_, isDirect := directNames[realName]
		refs = append(refs, PackageRef{
			Ecosystem: "pub",
			Name:      realName,
			Version:   entry.Version,
			Direct:    isDirect,
			Integrity: integrity,
		})
	}
	return refs
}
