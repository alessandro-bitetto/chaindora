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

// ResolveNPMTree returns every (pkg, version) that `npm install`
// would land on disk for the given install args, including
// transitives. The whole point of doing this BEFORE running the
// real install is so the gate can refuse the operation if any
// node in the tree fails a check — that's how we catch the
// transitive-dep attack class the user flagged.
//
// Implementation: shell out to `npm install --package-lock-only
// --no-audit --ignore-scripts` in a throwaway temp directory.
// npm's own resolver does the work; we parse the generated
// package-lock.json. `--ignore-scripts` is CRITICAL: postinstall
// payloads are exactly what we're trying to gate, so we must not
// let them run during the resolution step itself.
//
// npmPath is the absolute path to the real npm binary — passed in
// (not looked up via PATH) so the gate's own shim can't loop back
// into itself. Tests can pass "" to fall back to the system npm.
func ResolveNPMTree(ctx context.Context, npmPath string, installArgs []string) ([]PackageRef, error) {
	if len(installArgs) == 0 {
		return nil, errors.New("no install args supplied")
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-resolve-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	// Seed an empty package.json so npm doesn't refuse to operate.
	pkgJSON := `{"name":"chdora-gate-resolve","version":"0.0.0","private":true}`
	if err := os.WriteFile(filepath.Join(tmp, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		return nil, fmt.Errorf("seed package.json: %w", err)
	}

	npm := npmPath
	if npm == "" {
		npm = "npm"
	}
	// Strip flags the user might have passed that would block us
	// from getting the resolved lockfile back:
	//   --dry-run / -n  → npm refuses to write the lockfile, our
	//                     read fails
	//   --no-save       → harmless but redundant with our setup
	// Everything else (--save-dev, --global, --workspaces, ...)
	// passes through so the resolution matches what npm WOULD
	// install when we finally exec it for real.
	cleaned := make([]string, 0, len(installArgs))
	for _, a := range installArgs {
		if a == "--dry-run" || a == "-n" {
			continue
		}
		cleaned = append(cleaned, a)
	}
	args := append([]string{
		"install",
		"--package-lock-only",
		"--no-audit",
		"--no-fund",
		"--ignore-scripts",
		"--prefer-online", // don't hand us cached resolutions that may pre-date a CVE
	}, cleaned...)
	cmd := exec.CommandContext(ctx, npm, args...)
	cmd.Dir = tmp
	// Capture combined output for diagnostics on failure; npm's
	// errors are mostly on stderr but the resolver fault path
	// (404 on a typo'd package) shows up cleaner when combined.
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Preserve a snippet of npm's output so the user can debug
		// "did I typo the package name" without re-running.
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 400 {
			snippet = snippet[:400] + "..."
		}
		return nil, fmt.Errorf("npm install --package-lock-only failed: %w\n%s", err, snippet)
	}

	lockPath := filepath.Join(tmp, "package-lock.json")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("read generated lockfile: %w", err)
	}
	return parseNPMLockTree(data, installArgs)
}

// ResolveNPMUpdateAll resolves what `npm update` (no args) would land
// on disk in the user's CWD. It copies the user's package.json +
// package-lock.json into a throwaway temp dir, runs `npm update
// --package-lock-only --ignore-scripts` there, and parses the
// resulting lockfile. Returns the FULL post-update tree — the gate
// re-checks every node, since OSV state may have advanced since the
// prior install was vetted.
//
// Without a package.json in cwd we error cleanly: `npm update` itself
// would refuse, so chaindora matches that behavior with a useful
// message.
func ResolveNPMUpdateAll(ctx context.Context, npmPath, cwd string) ([]PackageRef, error) {
	pjPath := filepath.Join(cwd, "package.json")
	pjBytes, err := os.ReadFile(pjPath)
	if err != nil {
		return nil, fmt.Errorf("read package.json in %s: %w", cwd, err)
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-update-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	if err := os.WriteFile(filepath.Join(tmp, "package.json"), pjBytes, 0o644); err != nil {
		return nil, fmt.Errorf("seed package.json: %w", err)
	}
	if lockBytes, err := os.ReadFile(filepath.Join(cwd, "package-lock.json")); err == nil {
		if err := os.WriteFile(filepath.Join(tmp, "package-lock.json"), lockBytes, 0o644); err != nil {
			return nil, fmt.Errorf("seed package-lock.json: %w", err)
		}
	}

	npm := npmPath
	if npm == "" {
		npm = "npm"
	}
	cmd := exec.CommandContext(ctx, npm,
		"update",
		"--package-lock-only",
		"--no-audit",
		"--no-fund",
		"--ignore-scripts",
		"--prefer-online", // re-resolve against current registry state, not stale cache
	)
	cmd.Dir = tmp
	out, err := cmd.CombinedOutput()
	if err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 400 {
			snippet = snippet[:400] + "..."
		}
		return nil, fmt.Errorf("npm update --package-lock-only failed: %w\n%s", err, snippet)
	}
	data, err := os.ReadFile(filepath.Join(tmp, "package-lock.json"))
	if err != nil {
		return nil, fmt.Errorf("read updated lockfile: %w", err)
	}
	directs, _ := directsFromNPMManifest(pjBytes)
	return parseNPMLockTreeWithDirects(data, directs)
}

// directsFromNPMManifest extracts the names declared as direct deps
// in a package.json — the set the user actually wrote down. Used by
// ResolveNPMUpdateAll to mark direct vs transitive in the rendered
// gate output. Errors here are non-fatal upstream (we fall back to
// an empty map and just lose the direct/transitive distinction).
func directsFromNPMManifest(b []byte) (map[string]bool, error) {
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(b, &pkg); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for k := range pkg.Dependencies {
		out[k] = true
	}
	for k := range pkg.DevDependencies {
		out[k] = true
	}
	for k := range pkg.OptionalDependencies {
		out[k] = true
	}
	return out, nil
}

// parseNPMLockTree turns a package-lock.json v3 blob into PackageRefs.
// Marked direct=true for any package whose name appears in
// installArgs (the user asked for it explicitly); everything else
// is transitive.
func parseNPMLockTree(data []byte, installArgs []string) ([]PackageRef, error) {
	return parseNPMLockTreeWithDirects(data, directNamesFromArgs(installArgs))
}

// parseNPMLockTreeWithDirects is the inner implementation that takes
// a precomputed directs map. Used by both the install-args path
// (parseNPMLockTree) and the update-all path (ResolveNPMUpdateAll).
func parseNPMLockTreeWithDirects(data []byte, directs map[string]bool) ([]PackageRef, error) {
	var lock struct {
		Packages map[string]struct {
			Version  string `json:"version"`
			Resolved string `json:"resolved"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}

	// Dedup: when npm resolves multiple versions of the same
	// package (e.g. lodash@4 alongside lodash@3 in different
	// subtrees), the lockfile has both. The gate wants every
	// (name, version) pair checked exactly once, regardless of
	// where in the tree it shows up.
	seen := map[string]struct{}{}
	var refs []PackageRef
	for key, entry := range lock.Packages {
		if key == "" {
			continue
		}
		// Lockfile v3 keys are paths like "node_modules/<name>" or
		// "node_modules/<scope>/<name>". Deduped resolutions can
		// nest: "node_modules/foo/node_modules/bar" — we still
		// want bar checked, so we strip every "node_modules/" prefix
		// and the leading one and take the result.
		name := stripNodeModulesPath(key)
		if name == "" || entry.Version == "" {
			continue
		}
		// v0.11.1: detect git+url entries and emit them as a
		// pseudo "git" ecosystem so the git-URL trust evaluator
		// fires while registry-model checks (cooldown, OSV,
		// publisher, ...) skip them.
		if isGitResolvedURL(entry.Resolved) {
			ident := "git:" + name + "@" + entry.Resolved
			if _, ok := seen[ident]; ok {
				continue
			}
			seen[ident] = struct{}{}
			refs = append(refs, PackageRef{
				Ecosystem: "git",
				Name:      name,
				Version:   normalizeGitResolved(entry.Resolved),
				Direct:    directs[name],
			})
			continue
		}
		ident := name + "@" + entry.Version
		if _, ok := seen[ident]; ok {
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

// isGitResolvedURL reports whether a package-lock.json `resolved`
// value points at a git source rather than a tarball. npm uses
// the `git+` prefix on the URL for git-protocol installs;
// historically `git://` and bare-git-ssh appear too.
func isGitResolvedURL(s string) bool {
	if s == "" {
		return false
	}
	low := strings.ToLower(s)
	return strings.HasPrefix(low, "git+") ||
		strings.HasPrefix(low, "git://") ||
		strings.HasPrefix(low, "git@") ||
		strings.HasPrefix(low, "ssh://git@")
}

// normalizeGitResolved trims npm's `git+` prefix from a resolved
// URL so the gate-checker sees the actual scheme. The fragment
// (#<ref>) stays intact.
func normalizeGitResolved(s string) string {
	return strings.TrimPrefix(s, "git+")
}

// stripNodeModulesPath turns a lockfile key into a bare package name.
// "node_modules/lodash" → "lodash"
// "node_modules/@scope/pkg" → "@scope/pkg"
// "node_modules/foo/node_modules/bar" → "bar"  (nested dedupe entry)
// "" → "" (the root package)
func stripNodeModulesPath(key string) string {
	idx := strings.LastIndex(key, "node_modules/")
	if idx < 0 {
		return ""
	}
	return key[idx+len("node_modules/"):]
}

// directNamesFromArgs picks out the package names from a list of
// npm install args. Accepts:
//
//	"lodash"            → lodash
//	"lodash@4.17.21"    → lodash
//	"@scope/pkg@1.0"    → @scope/pkg
//	"@scope/pkg"        → @scope/pkg
//
// Flags (anything starting with "-") are skipped. URL / git / file
// install targets fall through unchanged — we surface them as the
// "name" the gate sees, which lets the user spot weird specs in
// the rendered tree.
func directNamesFromArgs(args []string) map[string]bool {
	out := map[string]bool{}
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		// Find the version @ — same scope-skip logic as the
		// allowlist's matchesEntry.
		atIdx := -1
		if strings.HasPrefix(a, "@") {
			if i := strings.Index(a[1:], "@"); i >= 0 {
				atIdx = i + 1
			}
		} else {
			atIdx = strings.Index(a, "@")
		}
		name := a
		if atIdx >= 0 {
			name = a[:atIdx]
		}
		out[name] = true
	}
	return out
}
