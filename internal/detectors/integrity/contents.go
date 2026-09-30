package integrity

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/alessandro-bitetto/chaindora/internal/artifacts"
	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/gate"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

const IncompleteID = "CHDORA-INTEGRITY-INCOMPLETE"

// VerifyNPMLock verifies installed regular files against digest-authenticated
// registry artifacts. Missing evidence is explicit, including offline cache
// misses; it never means the installed contents were successfully checked.
func (d *Detector) VerifyNPMLock(ctx context.Context, lockPath string) []findings.Finding {
	root := filepath.Dir(lockPath)
	installedInfo, installedErr := os.Lstat(filepath.Join(root, "node_modules"))
	if os.IsNotExist(installedErr) {
		return nil
	}
	failure := func(name string, err error) findings.Finding {
		return findings.Finding{
			Detector: "integrity:files", Category: findings.CategoryConfiguration,
			Ecosystem: inventory.EcosystemNPM, Name: name, VulnID: IncompleteID,
			Severity: findings.SeverityLow, Confidence: findings.ConfidenceHigh,
			SourcePath: lockPath, Summary: "Installed-file verification incomplete: " + err.Error(),
		}
	}
	if installedErr != nil {
		return []findings.Finding{failure("npm", installedErr)}
	}
	if !installedInfo.IsDir() {
		return []findings.Finding{failure("npm", fmt.Errorf("node_modules must be a directory, not a symlink"))}
	}
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return []findings.Finding{failure("npm", err)}
	}
	packages, err := gate.NPMLockPackages(data)
	if err != nil {
		return []findings.Finding{failure("npm", err)}
	}
	keys := make([]string, 0, len(packages))
	for key := range packages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	cache := map[string]*artifacts.Manifest{}
	var out []findings.Finding
	for _, key := range keys {
		pkg := packages[key]
		installed := filepath.Join(root, filepath.FromSlash(key))
		if _, err := os.Lstat(installed); os.IsNotExist(err) && pkg.Optional {
			continue
		}
		if err := artifacts.DirectoryPath(root, key); err != nil && !os.IsNotExist(err) {
			out = append(out, failure(pkg.Name, err))
			continue
		}
		m := cache[pkg.Integrity]
		if m == nil {
			bytes, err := artifacts.LoadNPM(ctx, d.HTTPClient, d.ArtifactCacheRoot, pkg.Resolved, pkg.Integrity, d.Offline)
			if err != nil {
				out = append(out, failure(pkg.Name, err))
				continue
			}
			m, err = artifacts.NPMManifest(bytes, pkg.Integrity)
			if err != nil {
				out = append(out, failure(pkg.Name, err))
				continue
			}
			cache[pkg.Integrity] = m
		}
		if m.Name != pkg.Name || m.Version != pkg.Version {
			out = append(out, failure(pkg.Name, fmt.Errorf("artifact identity differs from lockfile")))
			continue
		}
		diffs, err := artifacts.CompareFiles(installed, m)
		if err != nil {
			out = append(out, failure(pkg.Name, err))
		}
		for _, diff := range diffs {
			out = append(out, findings.Finding{
				Detector: "integrity:files", Category: findings.CategoryHostForensics,
				Ecosystem: inventory.EcosystemNPM, Name: pkg.Name, Version: pkg.Version,
				PURL:   inventory.PURL(inventory.EcosystemNPM, pkg.Name, pkg.Version),
				VulnID: "INTEGRITY-FILE-MISMATCH", Severity: findings.SeverityCritical,
				Confidence: findings.ConfidenceHigh, SourcePath: diff.Path, Integrity: pkg.Integrity,
				Summary: diff.Reason + " (verified against package-lock.json artifact digest)",
			})
		}
	}
	return out
}
