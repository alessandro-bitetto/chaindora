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

// ResolveBundlerTree resolves what `bundle add <gem>` would
// install, without actually installing. Approach:
//   1. tmpdir with a minimal Gemfile that requires every
//      requested gem.
//   2. `bundle lock --update` to compute the resolution.
//   3. Parse Gemfile.lock with the existing inventory parser
//      shape (4-space indented `name (version)` lines under
//      `GEM/specs:`).
//
// bundlerPath is the absolute path to the real `bundle` binary.
func ResolveBundlerTree(ctx context.Context, bundlerPath string, addArgs []string) ([]PackageRef, error) {
	if len(addArgs) == 0 {
		return nil, errors.New("no bundler add args supplied")
	}
	bundler := bundlerPath
	if bundler == "" {
		bundler = "bundle"
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-bundle-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	gems, err := parseBundleAddArgs(addArgs)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("source 'https://rubygems.org'\n\n")
	for _, g := range gems {
		if g.version != "" {
			fmt.Fprintf(&b, "gem %q, %q\n", g.name, g.version)
		} else {
			fmt.Fprintf(&b, "gem %q\n", g.name)
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, "Gemfile"), []byte(b.String()), 0o644); err != nil {
		return nil, err
	}

	// `bundle lock` resolves + writes Gemfile.lock without
	// running gem extensions. --no-cache avoids touching the
	// user's local Bundler cache for an ephemeral resolution.
	cmd := exec.CommandContext(ctx, bundler, "lock")
	cmd.Dir = tmp
	if out, err := cmd.CombinedOutput(); err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 400 {
			snippet = snippet[:400] + "..."
		}
		return nil, fmt.Errorf("bundle lock failed: %w\n%s", err, snippet)
	}

	data, err := os.ReadFile(filepath.Join(tmp, "Gemfile.lock"))
	if err != nil {
		return nil, fmt.Errorf("read generated Gemfile.lock: %w", err)
	}
	return parseGemfileLockTree(data, gems), nil
}

type bundleAddArg struct {
	name    string
	version string
}

func parseBundleAddArgs(args []string) ([]bundleAddArg, error) {
	var out []bundleAddArg
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		// `gem add NAME [--version V]` — but flags strip above
		// removes --version, so split on '@' too as a fallback
		// for `bundle add foo@1.0` shortcuts (not standard,
		// but some users adopt it).
		dep := bundleAddArg{name: a}
		if i := strings.Index(a, "@"); i > 0 {
			dep.name = a[:i]
			dep.version = a[i+1:]
		}
		out = append(out, dep)
	}
	if len(out) == 0 {
		return nil, errors.New("no resolvable gems in args")
	}
	return out, nil
}

// parseGemfileLockTree extracts (name, version) pairs from the
// GEM/specs: section of a Gemfile.lock. Same shape as the
// inventory module's parser but emits PackageRefs.
func parseGemfileLockTree(data []byte, directs []bundleAddArg) []PackageRef {
	directNames := map[string]struct{}{}
	for _, d := range directs {
		directNames[d.name] = struct{}{}
	}
	var refs []PackageRef
	seen := map[string]struct{}{}
	inGEM := false
	inSpecs := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if len(line) > 0 && line[0] != ' ' {
			inGEM = trimmed == "GEM"
			inSpecs = false
			continue
		}
		if !inGEM {
			continue
		}
		if trimmed == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}
		// 4-space indent = resolved spec line.
		if !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "      ") {
			continue
		}
		open := strings.LastIndex(trimmed, "(")
		closeIdx := strings.LastIndex(trimmed, ")")
		if open < 0 || closeIdx < open {
			continue
		}
		name := strings.TrimSpace(trimmed[:open])
		version := strings.TrimSpace(trimmed[open+1 : closeIdx])
		if name == "" || version == "" {
			continue
		}
		if strings.ContainsAny(version, "~<>=") {
			continue // dep constraint, not resolved
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		_, isDirect := directNames[name]
		refs = append(refs, PackageRef{
			Ecosystem: "rubygems",
			Name:      name,
			Version:   version,
			Direct:    isDirect,
		})
	}
	return refs
}
