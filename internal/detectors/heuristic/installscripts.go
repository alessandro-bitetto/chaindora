package heuristic

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// detectInstallScripts emits findings for:
//   1. Top-level `package.json` files in scanRoot that declare a
//      pre/post-install or install script (LOW — these are the project's
//      own scripts; an attacker who lands a commit can use them for
//      persistence).
//   2. npm dependencies whose lockfile entry sets `hasInstallScript: true`
//      (MEDIUM — most legitimate libraries don't ship install hooks; the
//      Shai-Hulud worm relies on this hook to propagate).
func detectInstallScripts(inv *inventory.Inventory, scanRoot string, excludes []string) []findings.Finding {
	var out []findings.Finding
	out = append(out, scanRootPackageScripts(scanRoot, excludes)...)
	out = append(out, scanDependencyInstallScripts(inv)...)
	return out
}

func scanRootPackageScripts(scanRoot string, excludes []string) []findings.Finding {
	excludeSet := map[string]struct{}{}
	for _, e := range excludes {
		if e != "" {
			excludeSet[e] = struct{}{}
		}
	}
	var out []findings.Finding
	_ = filepath.WalkDir(scanRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "node_modules" || name == ".git" || name == ".venv" || name == "venv" {
				return filepath.SkipDir
			}
			if _, skip := excludeSet[name]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Base(path) != "package.json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var pkg struct {
			Name    string            `json:"name"`
			Scripts map[string]string `json:"scripts"`
		}
		if err := json.Unmarshal(data, &pkg); err != nil {
			return nil
		}
		for _, hook := range []string{"preinstall", "install", "postinstall"} {
			cmd, ok := pkg.Scripts[hook]
			if !ok || strings.TrimSpace(cmd) == "" {
				continue
			}
			out = append(out, findings.Finding{
				Detector:  "heuristic:npm-install-script",
				Ecosystem: inventory.EcosystemNPM,
				Name:      pkg.Name,
				VulnID:    "HEUR-NPM-" + strings.ToUpper(hook) + "-OWN",
				Summary: fmt.Sprintf(
					"package.json declares an %q script: %q. Install-time scripts run automatically — review whether your project actually needs one.",
					hook, truncate(cmd, 120),
				),
				Severity:   findings.SeverityLow,
				SourcePath: path,
			})
		}
		return nil
	})
	return out
}

func scanDependencyInstallScripts(inv *inventory.Inventory) []findings.Finding {
	if inv == nil {
		return nil
	}
	var out []findings.Finding
	seen := map[string]bool{}
	for i := range inv.Packages {
		p := &inv.Packages[i]
		if p.Ecosystem != inventory.EcosystemNPM || !p.HasInstallScript {
			continue
		}
		key := p.Name + "@" + p.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, findings.Finding{
			Detector:  "heuristic:npm-install-script",
			PURL:      p.PURL,
			Ecosystem: p.Ecosystem,
			Name:      p.Name,
			Version:   p.Version,
			VulnID:    "HEUR-NPM-DEP-INSTALL-SCRIPT",
			Summary: fmt.Sprintf(
				"npm dependency %s@%s declares an install-time script. Most libraries don't need one; the Shai-Hulud worm relies on this hook to spread.",
				p.Name, p.Version,
			),
			Severity:   findings.SeverityMedium,
			SourcePath: p.SourcePath,
		})
	}
	return out
}
