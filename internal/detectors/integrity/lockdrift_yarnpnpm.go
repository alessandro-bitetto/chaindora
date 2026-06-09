package integrity

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// checkYarnLockfileVsDisk and checkPnpmLockfileVsDisk both layer
// on top of the npm inventory parser's output for their lockfile
// formats — yarn and pnpm install into `node_modules/` with the
// same per-package `package.json` shape as npm, so the
// version-drift and name-drift checks transfer verbatim.
//
// What does NOT transfer cleanly: the npm mirror lockfile
// (`node_modules/.package-lock.json`) is npm-specific. yarn/pnpm
// have their own install metadata layouts that we don't (yet)
// cross-check. Future work.

func (d *Detector) checkYarnLockfileVsDisk(ctx context.Context, lockPath string) []findings.Finding {
	// Yarn classic has no per-version install store to confirm against,
	// so version drift can't be graded (nil install record → medium).
	return checkJSPkgVersionDriftFromLockfile(lockPath, "yarn.lock", parseYarnLockNames, nil)
}

func (d *Detector) checkPnpmLockfileVsDisk(ctx context.Context, lockPath string) []findings.Finding {
	// pnpm's node_modules/.pnpm/<name>@<version>/ virtual store is its
	// authoritative record of what it installed — the pnpm analog of
	// npm's .package-lock.json mirror. Pass it so version drift can be
	// graded: a disk version the store knows about is staleness; one it
	// doesn't is a copy pnpm never placed (possible tamper).
	nodeModules := filepath.Join(filepath.Dir(lockPath), "node_modules")
	return checkJSPkgVersionDriftFromLockfile(lockPath, "pnpm-lock.yaml", parsePnpmLockNames, pnpmStoreVersions(nodeModules))
}

// checkJSPkgVersionDriftFromLockfile is the shared shape: take a
// JS lockfile of any flavor, extract its (name, version) pairs
// via the supplied parser, group by name, then for each unique
// name verify that `node_modules/<name>/package.json` reports a
// version that's in the set of pinned versions for that name.
//
// The unique-name + set-of-versions approach (rather than one
// check per lockfile entry) is the fix for the v0.15.0 bug where
// a package with multiple resolved versions in the lockfile —
// classic transitive-dep churn for semver / brace-expansion /
// minimatch / etc. — produced one false-positive drift finding
// per non-hoisted entry. Yarn / pnpm both record every resolved
// version in the lockfile but only one version ends up at the
// top-level `node_modules/<name>/` (the hoisted one); the others
// live nested or under .pnpm/. As long as the hoisted version
// matches SOMETHING the lockfile pins, there's no drift.
// installRecord maps package name → the set of versions a package
// manager's own install store actually placed on disk (pnpm's .pnpm/
// store). nil when the ecosystem has no such record (yarn classic).
func checkJSPkgVersionDriftFromLockfile(lockPath, kind string, parseFn func(string) []nameVersion, installRecord map[string]map[string]struct{}) []findings.Finding {
	projectDir := filepath.Dir(lockPath)
	nodeModules := filepath.Join(projectDir, "node_modules")
	if _, err := os.Stat(nodeModules); err != nil {
		return nil
	}
	entries := parseFn(lockPath)
	if len(entries) == 0 {
		return nil
	}
	// Group by name → set of pinned versions. yarn/pnpm both
	// happily ship the same name at multiple versions when
	// transitives demand it. aliasTarget records npm-alias
	// resolutions (yarn: `string-width-cjs@npm:string-width@…`) so the
	// name check compares against the declared target, not the install
	// directory name.
	pinned := map[string]map[string]struct{}{}
	aliasTarget := map[string]string{}
	for _, e := range entries {
		if pinned[e.name] == nil {
			pinned[e.name] = map[string]struct{}{}
		}
		pinned[e.name][e.version] = struct{}{}
		if e.aliasOf != "" {
			aliasTarget[e.name] = e.aliasOf
		}
	}
	var out []findings.Finding
	for name, versions := range pinned {
		pkgJSON := filepath.Join(nodeModules, name, "package.json")
		data, err := os.ReadFile(pkgJSON)
		if err != nil {
			continue
		}
		var disk struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal(data, &disk); err != nil {
			continue
		}
		// Version drift: on-disk version isn't in the lockfile's pinned
		// set for this name (and it's not just the hoisted copy with the
		// rest nested). Grade by confidence using the install record:
		//   - record knows this disk version (or no record available) →
		//     the install is self-consistent and only the lockfile is out
		//     of sync → MEDIUM staleness (the common `pnpm update`-without-
		//     reinstall churn).
		//   - record exists for this name but does NOT contain the disk
		//     version → the copy on disk was never placed by the package
		//     manager → CRITICAL (possible tamper).
		// The identity-swap case is independently caught by name-drift.
		if disk.Version != "" {
			if _, matches := versions[disk.Version]; !matches {
				pinnedList := versionSetToString(versions)
				sev := findings.SeverityMedium
				summary := fmt.Sprintf(
					"%s pins %s at %s but node_modules/%s/package.json reports version %q — installed tree is out of sync with the lockfile; reinstall to reconcile (if you didn't change the lockfile, investigate)",
					kind, name, pinnedList, name, disk.Version)
				if rec, known := installRecord[name]; known {
					if _, placed := rec[disk.Version]; !placed {
						sev = findings.SeverityCritical
						summary = fmt.Sprintf(
							"%s pins %s at %s but node_modules/%s/package.json reports version %q, which matches no version in pnpm's own node_modules/.pnpm store — the installed copy was not placed by pnpm (possible tamper)",
							kind, name, pinnedList, name, disk.Version)
					}
				}
				out = append(out, findings.Finding{
					Detector:   "integrity:lockfile-vs-disk-version",
					Category:   findings.CategoryHostForensics,
					Ecosystem:  inventory.EcosystemNPM,
					Name:       name,
					Version:    pinnedList,
					PURL:       inventory.PURL(inventory.EcosystemNPM, name, pinnedList),
					VulnID:     "INTEGRITY-DRIFT-VERSION",
					Summary:    summary,
					Severity:   sev,
					SourcePath: lockPath,
				})
			}
		}
		// Name drift: compare the on-disk package name against the
		// declared alias target when this entry is an alias, else the
		// directory name. A legitimate alias (disk name == target) is
		// silent; a genuine swap (disk name ≠ target/dir) still fires.
		expectedName := name
		if t := aliasTarget[name]; t != "" {
			expectedName = t
		}
		if disk.Name != "" && disk.Name != expectedName {
			out = append(out, findings.Finding{
				Detector:  "integrity:lockfile-vs-disk-name",
				Category:  findings.CategoryHostForensics,
				Ecosystem: inventory.EcosystemNPM,
				Name:      name,
				Version:   versionSetToString(versions),
				PURL:      inventory.PURL(inventory.EcosystemNPM, name, "any"),
				VulnID:    "INTEGRITY-DRIFT-NAME",
				Summary: fmt.Sprintf(
					"%s records %s but node_modules/%s/package.json identifies as %q (expected %q) — directory replaced or symlinked",
					kind, name, name, disk.Name, expectedName),
				Severity:   findings.SeverityCritical,
				SourcePath: lockPath,
			})
		}
	}
	return out
}

// versionSetToString stringifies a set of pinned versions for a
// finding's Version field + summary. Sorted for determinism.
func versionSetToString(set map[string]struct{}) string {
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	if len(out) == 1 {
		return out[0]
	}
	sortStrings(out)
	return "{" + joinStrings(out, ", ") + "}"
}

// sortStrings + joinStrings: tiny in-place helpers so we don't
// pull `sort` and `strings` for one call site each.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func joinStrings(s []string, sep string) string {
	if len(s) == 0 {
		return ""
	}
	out := s[0]
	for _, v := range s[1:] {
		out += sep + v
	}
	return out
}

// pnpmStoreVersions reads node_modules/.pnpm and returns name → set of
// installed versions. pnpm names its virtual-store directories
// `<name>@<version>` (`@scope+name@<version>` for scoped packages), with
// an optional peer-deps suffix (`_<hash>` in pnpm v6, `(<peers>)` in
// v7+). This is pnpm's authoritative record of what it placed on disk —
// the analog of npm's node_modules/.package-lock.json. Returns nil when
// there's no .pnpm store (e.g. node_modules wasn't pnpm-installed), in
// which case version drift is left at medium (we can't confirm tamper).
func pnpmStoreVersions(nodeModules string) map[string]map[string]struct{} {
	ents, err := os.ReadDir(filepath.Join(nodeModules, ".pnpm"))
	if err != nil {
		return nil
	}
	out := map[string]map[string]struct{}{}
	for _, e := range ents {
		// .pnpm contains a node_modules/ dir and a lock.yaml file
		// alongside the per-package dirs — skip anything that isn't a
		// <name>@<version> directory.
		if !e.IsDir() || e.Name() == "node_modules" {
			continue
		}
		name, version := parsePnpmStoreDir(e.Name())
		if name == "" || version == "" {
			continue
		}
		if out[name] == nil {
			out[name] = map[string]struct{}{}
		}
		out[name][version] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parsePnpmStoreDir extracts (name, version) from a .pnpm store directory
// name: "lodash@4.17.21", "@babel+core@7.28.0", "react@18.2.0_react@…"
// (v6 peer suffix), "react@18.2.0(react@…)" (v7+ peer suffix).
func parsePnpmStoreDir(d string) (name, version string) {
	// Strip the peer-deps suffix so it doesn't pollute the version.
	if i := strings.IndexAny(d, "(_"); i >= 0 {
		d = d[:i]
	}
	at := strings.LastIndex(d, "@")
	if at <= 0 {
		return "", ""
	}
	name, version = d[:at], d[at+1:]
	if strings.HasPrefix(name, "@") {
		// Scoped: pnpm encodes the "/" separator as "+".
		name = strings.Replace(name, "+", "/", 1)
	}
	return name, version
}

// nameVersion is a tiny tuple used by the parser callbacks. aliasOf
// carries the real package name when the entry is an npm alias (yarn),
// so the name-drift check compares the on-disk name against the declared
// target rather than the install-directory name.
type nameVersion struct {
	name    string
	version string
	aliasOf string
}

// parseYarnLockNames extracts (name, version) pairs from a yarn.lock
// (v1 or Berry). We piggy-back on the inventory parser to avoid
// re-implementing both formats — it's already battle-tested for
// edge cases (scope-prefixed names, comma-joined aliases, etc.).
func parseYarnLockNames(path string) []nameVersion {
	pkgs, err := inventory.ParseYarnLock(path)
	if err != nil {
		return nil
	}
	out := make([]nameVersion, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, nameVersion{name: p.Name, version: p.Version, aliasOf: p.AliasOf})
	}
	return out
}

func parsePnpmLockNames(path string) []nameVersion {
	pkgs, err := inventory.ParsePnpmLock(path)
	if err != nil {
		return nil
	}
	out := make([]nameVersion, 0, len(pkgs))
	for _, p := range pkgs {
		// pnpm keys its packages: map on the real name, so AliasOf is
		// always empty here — included for symmetry with the yarn path.
		out = append(out, nameVersion{name: p.Name, version: p.Version, aliasOf: p.AliasOf})
	}
	return out
}
