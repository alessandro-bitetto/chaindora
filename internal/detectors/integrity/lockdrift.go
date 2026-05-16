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

// checkNPMLockfileVsDisk verifies that what `package-lock.json` says
// is installed actually matches what's on disk under `node_modules/`.
//
// The threat model: lockfile-vs-registry (`checkGoSum`) catches the
// case where the lockfile itself was tampered with. lockfile-vs-disk
// catches the case where the bytes under node_modules were swapped
// AFTER install — by a malicious postinstall script in another
// package, a worm artifact, or a manual edit by an attacker who
// gained file-level access. Both checks live here because both
// answer the question "is what I'm running actually what was vetted?"
//
// Three concrete drifts we detect today:
//
//  1. **Version drift** — `package-lock.json` pins `lodash@4.17.21`,
//     `node_modules/lodash/package.json` reports `4.17.20`. Either
//     the install never completed or someone swapped the directory.
//     Severity: CRITICAL.
//
//  2. **Name drift** — `node_modules/lodash/package.json` reports
//     `name: "evil-lodash"`. Directory was replaced wholesale.
//     Severity: CRITICAL.
//
//  3. **Mirror-lockfile drift** — npm 7+ writes
//     `node_modules/.package-lock.json` mirroring the project's
//     lockfile. If integrity for the same `name@version` differs
//     between the two, someone modified one without the other.
//     Severity: CRITICAL.
//
// Future: byte-level recompute of the .tgz hash from cached tarballs
// (npm stores them under `~/.npm/_cacache/`) — adds defense against
// the case where both lockfiles agree on a hash but the installed
// bytes don't. Out of scope for v0.15 first cut.
func (d *Detector) checkNPMLockfileVsDisk(ctx context.Context, lockPath string) []findings.Finding {
	projectDir := filepath.Dir(lockPath)
	nodeModules := filepath.Join(projectDir, "node_modules")
	if _, err := os.Stat(nodeModules); err != nil {
		// No node_modules adjacent — nothing to check. Either the
		// project hasn't been installed, or it uses a workspace
		// arrangement we don't model.
		return nil
	}

	lockData, err := os.ReadFile(lockPath)
	if err != nil {
		return nil
	}
	var lock struct {
		Packages map[string]struct {
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(lockData, &lock); err != nil {
		return nil
	}
	if len(lock.Packages) == 0 {
		return nil
	}

	// Read the mirror lockfile if present; used by check #3.
	mirrorIntegrity := map[string]string{} // name@version → integrity
	if data, err := os.ReadFile(filepath.Join(nodeModules, ".package-lock.json")); err == nil {
		var mirror struct {
			Packages map[string]struct {
				Version   string `json:"version"`
				Integrity string `json:"integrity"`
			} `json:"packages"`
		}
		if json.Unmarshal(data, &mirror) == nil {
			for k, v := range mirror.Packages {
				if v.Integrity == "" || v.Version == "" {
					continue
				}
				name := npmKeyToName(k)
				if name == "" {
					continue
				}
				mirrorIntegrity[name+"@"+v.Version] = v.Integrity
			}
		}
	}

	var out []findings.Finding
	for key, entry := range lock.Packages {
		name := npmKeyToName(key)
		if name == "" || entry.Version == "" {
			continue
		}

		// Walk to the actual directory. `node_modules/<name>` or
		// `node_modules/<scope>/<name>` for scoped packages.
		pkgJSON := filepath.Join(nodeModules, name, "package.json")
		diskData, err := os.ReadFile(pkgJSON)
		if err == nil {
			// Check #1 + #2: name + version drift.
			var disk struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if json.Unmarshal(diskData, &disk) == nil {
				if disk.Version != "" && disk.Version != entry.Version {
					out = append(out, findings.Finding{
						Detector:  "integrity:lockfile-vs-disk-version",
						Category:  findings.CategoryHostForensics,
						Ecosystem: inventory.EcosystemNPM,
						Name:      name,
						Version:   entry.Version,
						PURL:      inventory.PURL(inventory.EcosystemNPM, name, entry.Version),
						VulnID:    "INTEGRITY-DRIFT-VERSION",
						Summary: fmt.Sprintf(
							"package-lock.json pins %s@%s but node_modules/%s/package.json reports version %q — installed bytes do not match the lockfile",
							name, entry.Version, name, disk.Version),
						Severity:   findings.SeverityCritical,
						SourcePath: lockPath,
					})
				}
				if disk.Name != "" && disk.Name != name {
					out = append(out, findings.Finding{
						Detector:  "integrity:lockfile-vs-disk-name",
						Category:  findings.CategoryHostForensics,
						Ecosystem: inventory.EcosystemNPM,
						Name:      name,
						Version:   entry.Version,
						PURL:      inventory.PURL(inventory.EcosystemNPM, name, entry.Version),
						VulnID:    "INTEGRITY-DRIFT-NAME",
						Summary: fmt.Sprintf(
							"lockfile records %s@%s but node_modules/%s/package.json identifies as %q — directory replaced or symlinked to a different package",
							name, entry.Version, name, disk.Name),
						Severity:   findings.SeverityCritical,
						SourcePath: lockPath,
					})
				}
			}
		}

		// Check #3: mirror lockfile drift.
		if entry.Integrity != "" {
			if m, ok := mirrorIntegrity[name+"@"+entry.Version]; ok && m != entry.Integrity {
				out = append(out, findings.Finding{
					Detector:  "integrity:lockfile-mirror-drift",
					Category:  findings.CategoryHostForensics,
					Ecosystem: inventory.EcosystemNPM,
					Name:      name,
					Version:   entry.Version,
					PURL:      inventory.PURL(inventory.EcosystemNPM, name, entry.Version),
					VulnID:    "INTEGRITY-MIRROR-DRIFT",
					Summary: fmt.Sprintf(
						"package-lock.json records integrity %q for %s@%s, node_modules/.package-lock.json records %q — one lockfile was modified without the other",
						truncateHash(entry.Integrity), name, entry.Version, truncateHash(m)),
					Severity:   findings.SeverityCritical,
					SourcePath: lockPath,
				})
			}
		}
	}
	return out
}

// npmKeyToName extracts a package name from a v2/v3 lockfile key
// like "node_modules/lodash" or "node_modules/@scope/pkg/node_modules/inner".
// For nested duplicates, we take the LEAF — that's where the actual
// directory lives on disk.
func npmKeyToName(k string) string {
	idx := strings.LastIndex(k, "node_modules/")
	if idx < 0 {
		return ""
	}
	return k[idx+len("node_modules/"):]
}

// truncateHash keeps the algorithm prefix and the first 12 hex/base64
// chars so the diff fits in a one-line finding summary.
func truncateHash(h string) string {
	if i := strings.IndexAny(h, "-:"); i > 0 && i < 10 {
		head := h[:i+1]
		body := h[i+1:]
		if len(body) > 12 {
			body = body[:12] + "..."
		}
		return head + body
	}
	if len(h) > 16 {
		return h[:16] + "..."
	}
	return h
}
