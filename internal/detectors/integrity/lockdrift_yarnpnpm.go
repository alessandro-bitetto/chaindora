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
// via the supplied parser, then for each one verify that
// `node_modules/<name>/package.json` reports a matching version
// and name. Mismatches emit a critical host-forensics finding.
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
	var out []findings.Finding
	for _, e := range entries {
		pkgJSON := filepath.Join(nodeModules, e.name, "package.json")
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
		if disk.Version != "" && disk.Version != e.version {
			out = append(out, findings.Finding{
				Detector:  "integrity:lockfile-vs-disk-version",
				Category:  findings.CategoryHostForensics,
				Ecosystem: inventory.EcosystemNPM,
				Name:      e.name,
				Version:   e.version,
				PURL:      inventory.PURL(inventory.EcosystemNPM, e.name, e.version),
				VulnID:    "INTEGRITY-DRIFT-VERSION",
				Summary: fmt.Sprintf(
					"%s pins %s@%s but node_modules/%s/package.json reports version %q — installed bytes do not match the lockfile",
					kind, e.name, e.version, e.name, disk.Version),
				Severity:   findings.SeverityCritical,
				SourcePath: lockPath,
			})
		}
		if disk.Name != "" && disk.Name != e.name {
			out = append(out, findings.Finding{
				Detector:  "integrity:lockfile-vs-disk-name",
				Category:  findings.CategoryHostForensics,
				Ecosystem: inventory.EcosystemNPM,
				Name:      e.name,
				Version:   e.version,
				PURL:      inventory.PURL(inventory.EcosystemNPM, e.name, e.version),
				VulnID:    "INTEGRITY-DRIFT-NAME",
				Summary: fmt.Sprintf(
					"%s records %s@%s but node_modules/%s/package.json identifies as %q — directory replaced or symlinked",
					kind, e.name, e.version, e.name, disk.Name),
				Severity:   findings.SeverityCritical,
				SourcePath: lockPath,
			})
		}
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
