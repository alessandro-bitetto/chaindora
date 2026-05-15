package heuristic

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// Install-script evidence thresholds. Install hooks in a 10-year-old
// 50M-weekly-downloads package (husky, esbuild, node-gyp, fsevents,
// ...) aren't a signal of anything. Install hooks in a 3-week-old
// 50-weekly-downloads package are highly suspicious — this is exactly
// the shape the Shai-Hulud worm rides.
const (
	installScriptSuspiciousAgeDays    = 90
	installScriptSuspiciousDownloads7d = 5000
)

// detectInstallScripts emits findings for:
//   1. Top-level `package.json` files in scanRoot that declare a
//      pre/post-install or install script (LOW — these are the project's
//      own scripts; an attacker who lands a commit can use them for
//      persistence).
//   2. npm dependencies whose lockfile entry sets `hasInstallScript: true`
//      AND for which registry evidence supports "fresh and/or low-traffic"
//      (the Shai-Hulud worm rides exactly this shape). v0.6.0 gates the
//      dependency-side finding behind registry evidence so we stop
//      flagging widely-used utility packages whose install hooks are
//      legitimate (esbuild, husky, node-gyp, fsevents, sharp, ...).
func detectInstallScripts(ctx context.Context, inv *inventory.Inventory, scanRoot string, excludes []string, cfg Config) []findings.Finding {
	var out []findings.Finding
	out = append(out, scanRootPackageScripts(scanRoot, excludes)...)
	out = append(out, scanDependencyInstallScripts(ctx, inv, cfg)...)
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
			// Same shared skip set as the other walkers — testdata,
			// .vscode, .cursor, Go modcache, etc. Bypass for the
			// root itself so explicit `chdora scan testdata` still
			// finds install-script patterns there if asked.
			if path != scanRoot && inventory.ShouldSkipDir(path, name) {
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

func scanDependencyInstallScripts(ctx context.Context, inv *inventory.Inventory, cfg Config) []findings.Finding {
	if inv == nil {
		return nil
	}
	npm := cfg.npm()
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

		// Evidence: how young is the package, how much real-world adoption?
		pub, _ := npm.PublishedAt(ctx, p.Name)
		dl, _ := npm.DownloadsLast7d(ctx, p.Name)

		// No evidence at all → don't fire. We'd rather under-report
		// than swamp the user with legitimate husky/esbuild/sharp etc.
		if pub.IsZero() && dl < 0 {
			continue
		}

		ageDays := -1
		if !pub.IsZero() {
			ageDays = int(time.Since(pub).Hours() / 24)
		}
		// Mature AND well-adopted: suppress.
		if ageDays >= 0 && ageDays > installScriptSuspiciousAgeDays && dl > installScriptSuspiciousDownloads7d {
			continue
		}
		// Mature (years old) regardless of downloads: long-tail legitimate
		// tooling, skip.
		if ageDays > 365 {
			continue
		}

		var severity findings.Severity
		switch {
		case ageDays >= 0 && ageDays <= 7:
			severity = findings.SeverityCritical
		case ageDays >= 0 && ageDays <= 30:
			severity = findings.SeverityHigh
		default:
			severity = findings.SeverityMedium
		}

		msg := fmt.Sprintf("npm dependency %s@%s declares an install-time script", p.Name, p.Version)
		if ageDays >= 0 {
			msg += fmt.Sprintf(", published %d day(s) ago", ageDays)
		}
		if dl >= 0 {
			msg += fmt.Sprintf(", %d downloads/week", dl)
		}
		msg += ". This is the shape the Shai-Hulud worm rides — verify the install hook is intentional."

		out = append(out, findings.Finding{
			Detector:   "heuristic:npm-install-script",
			PURL:       p.PURL,
			Ecosystem:  p.Ecosystem,
			Name:       p.Name,
			Version:    p.Version,
			VulnID:     "HEUR-NPM-DEP-INSTALL-SCRIPT",
			Summary:    msg,
			Severity:   severity,
			SourcePath: p.SourcePath,
		})
	}
	return out
}
