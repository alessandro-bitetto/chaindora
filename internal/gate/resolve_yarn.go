package gate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ResolveYarnTree returns every (pkg, version) that `yarn add`
// (Yarn classic v1) or `yarn add` (Berry v2+) would land on disk
// for the supplied args, including transitives. Same posture as
// the npm resolver: run yarn in a throwaway tmpdir with
// `--ignore-scripts`, parse the generated lockfile, treat the
// resolved tree as the unit of work for the gate.
//
// We detect Berry vs classic by trying Berry's mode first
// (`yarn add --mode=update-lockfile`) and falling back to
// classic if yarn refuses the flag — Berry's CLI rejects
// classic args and vice-versa. This is unfortunately the only
// reliable detection: `yarn --version` lies inside corepack
// shims.
//
// yarnPath is the absolute path to the real yarn binary (not
// the shim) — same recursion-guard pattern as ResolveNPMTree.
func ResolveYarnTree(ctx context.Context, yarnPath string, addArgs []string) ([]PackageRef, error) {
	if len(addArgs) == 0 {
		return nil, errors.New("no add args supplied")
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-yarn-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	pkgJSON := `{"name":"chdora-gate-resolve","version":"0.0.0","private":true}`
	if err := os.WriteFile(filepath.Join(tmp, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		return nil, fmt.Errorf("seed package.json: %w", err)
	}

	yarn := yarnPath
	if yarn == "" {
		yarn = "yarn"
	}
	// Strip flags that would prevent us from getting the lockfile.
	cleaned := stripYarnNetFlags(addArgs)

	// Berry attempt: --mode=update-lockfile is the Berry idiom
	// for "resolve, write lockfile, don't install".
	berryArgs := append([]string{"add", "--mode=update-lockfile"}, cleaned...)
	berryCmd := exec.CommandContext(ctx, yarn, berryArgs...)
	berryCmd.Dir = tmp
	if out, err := berryCmd.CombinedOutput(); err == nil {
		return parseYarnLock(tmp, addArgs)
	} else {
		// Fall through to classic. Surface Berry's error if
		// classic also fails so the user can see both attempts.
		_ = out
	}
	// Classic yarn: `yarn add` writes yarn.lock + node_modules.
	// We pass `--ignore-scripts` for the same reason as npm —
	// no postinstall during the gate's resolution step.
	classicArgs := append([]string{"add", "--ignore-scripts", "--no-progress"}, cleaned...)
	classicCmd := exec.CommandContext(ctx, yarn, classicArgs...)
	classicCmd.Dir = tmp
	if out, err := classicCmd.CombinedOutput(); err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 400 {
			snippet = snippet[:400] + "..."
		}
		return nil, fmt.Errorf("yarn add failed (Berry and classic both refused): %w\n%s", err, snippet)
	}
	return parseYarnLock(tmp, addArgs)
}

// parseYarnLock reads either yarn.lock format (v1 or Berry) and
// returns the resolved tree. Both formats are line-oriented; we
// don't try to reimplement a full yarn parser, just extract the
// (name, version) pairs that's all the gate needs.
func parseYarnLock(dir string, addArgs []string) ([]PackageRef, error) {
	data, err := os.ReadFile(filepath.Join(dir, "yarn.lock"))
	if err != nil {
		return nil, fmt.Errorf("read yarn.lock: %w", err)
	}
	// Try Berry (YAML-ish) first. Berry's yarn.lock has a
	// "__metadata:" stanza and uses YAML-style key: value.
	if strings.Contains(string(data), "__metadata:") {
		return parseYarnBerryLock(data, addArgs)
	}
	return parseYarnClassicLock(data, addArgs)
}

// parseYarnClassicLock parses Yarn v1 lockfile format. Format:
//
//	pkg@^1.0.0:
//	  version "1.2.3"
//	  resolved "..."
//
// We scan for `version "X"` lines paired with the immediately-
// preceding stanza header.
func parseYarnClassicLock(data []byte, addArgs []string) ([]PackageRef, error) {
	directs := directNamesFromArgs(addArgs)
	seen := map[string]struct{}{}
	var refs []PackageRef

	lines := strings.Split(string(data), "\n")
	var currentName string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Stanza header line — not indented, ends with ':'
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
			// "@scope/pkg@^1.0.0, @scope/pkg@~1.1.0:" — the
			// first comma-separated spec gives us the package.
			spec := strings.TrimSuffix(trimmed, ":")
			if i := strings.Index(spec, ","); i >= 0 {
				spec = spec[:i]
			}
			spec = strings.Trim(spec, `"`)
			// Strip the version-range suffix: name is everything
			// up to the LAST '@' (scope-safe).
			atIdx := -1
			if strings.HasPrefix(spec, "@") {
				if i := strings.Index(spec[1:], "@"); i >= 0 {
					atIdx = i + 1
				}
			} else {
				atIdx = strings.LastIndex(spec, "@")
			}
			if atIdx > 0 {
				currentName = spec[:atIdx]
			}
			continue
		}
		// `  version "1.2.3"` — extract the version string.
		if strings.HasPrefix(trimmed, "version ") {
			ver := strings.TrimSpace(strings.TrimPrefix(trimmed, "version"))
			ver = strings.Trim(ver, `"`)
			if currentName == "" || ver == "" {
				continue
			}
			ident := currentName + "@" + ver
			if _, dup := seen[ident]; dup {
				continue
			}
			seen[ident] = struct{}{}
			refs = append(refs, PackageRef{
				Ecosystem: "npm",
				Name:      currentName,
				Version:   ver,
				Direct:    directs[currentName],
			})
		}
	}
	return refs, nil
}

// parseYarnBerryLock parses Yarn Berry's YAML-ish lockfile. The
// format is YAML-compatible apart from the `__metadata:` stanza,
// so we strip that and let the YAML parser do the rest.
func parseYarnBerryLock(data []byte, addArgs []string) ([]PackageRef, error) {
	directs := directNamesFromArgs(addArgs)
	// Berry's stanza shape:
	//   "pkg@npm:^1.0.0":
	//     version: 1.2.3
	//     resolution: "pkg@npm:1.2.3"
	var raw map[string]struct {
		Version    string `yaml:"version"`
		Resolution string `yaml:"resolution"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse berry yarn.lock: %w", err)
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	for key, entry := range raw {
		if entry.Version == "" {
			continue
		}
		// Key shape: "pkg@npm:^1.0.0, pkg@npm:~1.1.0".
		// Extract the package name (strip protocol + range).
		spec := key
		if i := strings.Index(spec, ","); i >= 0 {
			spec = spec[:i]
		}
		name := yarnBerryName(spec)
		if name == "" {
			continue
		}
		ident := name + "@" + entry.Version
		if _, dup := seen[ident]; dup {
			continue
		}
		seen[ident] = struct{}{}
		refs = append(refs, PackageRef{
			Ecosystem: "npm",
			Name:      name,
			Version:   entry.Version,
			Direct:    directs[name],
		})
	}
	return refs, nil
}

// yarnBerryName extracts "@scope/pkg" or "pkg" from a Berry
// spec like "pkg@npm:^1.0.0" or "@scope/pkg@npm:^1.0.0".
func yarnBerryName(spec string) string {
	atIdx := -1
	if strings.HasPrefix(spec, "@") {
		if i := strings.Index(spec[1:], "@"); i >= 0 {
			atIdx = i + 1
		}
	} else {
		atIdx = strings.Index(spec, "@")
	}
	if atIdx <= 0 {
		return ""
	}
	return spec[:atIdx]
}

// ResolveYarnUpdateAll resolves what `yarn upgrade` (classic, no args)
// or `yarn up` (Berry) would land on disk. Copies the user's
// package.json and yarn.lock into a temp dir and runs yarn in a
// lockfile-only mode there.
//
// Same Berry-vs-classic two-step as ResolveYarnTree: try Berry's
// `yarn up --mode=update-lockfile` first, fall back to classic
// `yarn upgrade --silent --ignore-scripts` on rejection.
func ResolveYarnUpdateAll(ctx context.Context, yarnPath, cwd string) ([]PackageRef, error) {
	pjPath := filepath.Join(cwd, "package.json")
	pjBytes, err := os.ReadFile(pjPath)
	if err != nil {
		return nil, fmt.Errorf("read package.json in %s: %w", cwd, err)
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-yarn-update-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	if err := os.WriteFile(filepath.Join(tmp, "package.json"), pjBytes, 0o644); err != nil {
		return nil, fmt.Errorf("seed package.json: %w", err)
	}
	if lockBytes, err := os.ReadFile(filepath.Join(cwd, "yarn.lock")); err == nil {
		if err := os.WriteFile(filepath.Join(tmp, "yarn.lock"), lockBytes, 0o644); err != nil {
			return nil, fmt.Errorf("seed yarn.lock: %w", err)
		}
	}

	yarn := yarnPath
	if yarn == "" {
		yarn = "yarn"
	}

	// Berry: `yarn up '*' --mode=update-lockfile` bumps everything
	// without writing node_modules.
	berryCmd := exec.CommandContext(ctx, yarn, "up", "*", "--mode=update-lockfile")
	berryCmd.Dir = tmp
	if _, err := berryCmd.CombinedOutput(); err == nil {
		return parseYarnLock(tmp, nil)
	}

	// Classic: `yarn upgrade --silent --ignore-scripts` upgrades every
	// dep to the newest in-range version and rewrites yarn.lock.
	classicCmd := exec.CommandContext(ctx, yarn, "upgrade", "--silent", "--ignore-scripts", "--no-progress")
	classicCmd.Dir = tmp
	if out, err := classicCmd.CombinedOutput(); err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 400 {
			snippet = snippet[:400] + "..."
		}
		return nil, fmt.Errorf("yarn upgrade failed (Berry and classic both refused): %w\n%s", err, snippet)
	}
	return parseYarnLock(tmp, nil)
}

// stripYarnNetFlags removes args that would prevent us from
// getting the lockfile. yarn classic's `--dry-run` skips the
// lockfile write; Berry doesn't have it but accepts other
// pass-through flags fine.
func stripYarnNetFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--dry-run" {
			continue
		}
		out = append(out, a)
	}
	return out
}

// readYarnLock is a small helper used only in tests — exported
// indirectly via parseYarnClassicLock / parseYarnBerryLock for
// the resolver tests.
func readYarnLock(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
