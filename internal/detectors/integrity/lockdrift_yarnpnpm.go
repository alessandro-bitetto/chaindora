package integrity

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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
	return checkJSPkgVersionDriftFromLockfile(lockPath, "yarn.lock", parseYarnLockNames)
}

func (d *Detector) checkPnpmLockfileVsDisk(ctx context.Context, lockPath string) []findings.Finding {
	return checkJSPkgVersionDriftFromLockfile(lockPath, "pnpm-lock.yaml", parsePnpmLockNames)
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
func checkJSPkgVersionDriftFromLockfile(lockPath, kind string, parseFn func(string) []nameVersion) []findings.Finding {
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
	// transitives demand it.
	pinned := map[string]map[string]struct{}{}
	for _, e := range entries {
		if pinned[e.name] == nil {
			pinned[e.name] = map[string]struct{}{}
		}
		pinned[e.name][e.version] = struct{}{}
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
		// Drift only if on-disk version doesn't match ANY pinned
		// version for this name. Otherwise the on-disk copy is
		// just the hoisted one and the rest live nested.
		if disk.Version != "" {
			if _, matches := versions[disk.Version]; !matches {
				pinnedList := versionSetToString(versions)
				out = append(out, findings.Finding{
					Detector:  "integrity:lockfile-vs-disk-version",
					Category:  findings.CategoryHostForensics,
					Ecosystem: inventory.EcosystemNPM,
					Name:      name,
					Version:   pinnedList,
					PURL:      inventory.PURL(inventory.EcosystemNPM, name, pinnedList),
					VulnID:    "INTEGRITY-DRIFT-VERSION",
					Summary: fmt.Sprintf(
						"%s pins %s at %s but node_modules/%s/package.json reports version %q — installed bytes do not match any pinned version",
						kind, name, pinnedList, name, disk.Version),
					Severity:   findings.SeverityCritical,
					SourcePath: lockPath,
				})
			}
		}
		if disk.Name != "" && disk.Name != name {
			out = append(out, findings.Finding{
				Detector:  "integrity:lockfile-vs-disk-name",
				Category:  findings.CategoryHostForensics,
				Ecosystem: inventory.EcosystemNPM,
				Name:      name,
				Version:   versionSetToString(versions),
				PURL:      inventory.PURL(inventory.EcosystemNPM, name, "any"),
				VulnID:    "INTEGRITY-DRIFT-NAME",
				Summary: fmt.Sprintf(
					"%s records %s but node_modules/%s/package.json identifies as %q — directory replaced or symlinked",
					kind, name, name, disk.Name),
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

// nameVersion is a tiny tuple used by the parser callbacks.
type nameVersion struct {
	name    string
	version string
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
		out = append(out, nameVersion{name: p.Name, version: p.Version})
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
		out = append(out, nameVersion{name: p.Name, version: p.Version})
	}
	return out
}
