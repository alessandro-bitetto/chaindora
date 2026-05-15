package incident

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/incidents"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
	"github.com/alessandro-bitetto/chaindora/internal/progress"
)

type Detector struct {
	incs     []*incidents.Incident
	excludes map[string]struct{}
}

func New(incs []*incidents.Incident, excludes ...string) *Detector {
	exSet := map[string]struct{}{}
	for _, e := range excludes {
		if e != "" {
			exSet[e] = struct{}{}
		}
	}
	return &Detector{incs: incs, excludes: exSet}
}

// Detect runs incident-pack matching against the inventory and a filesystem
// walk of scanRoot. Two finding sources:
//  1. Package name+version matches in the inventory.
//  2. File artifacts whose glob matches a file under scanRoot, optionally
//     gated by a content substring.
func (d *Detector) Detect(ctx context.Context, inv *inventory.Inventory, scanRoot string) ([]findings.Finding, error) {
	if len(d.incs) == 0 {
		return nil, nil
	}

	var out []findings.Finding

	// Layer 1 — package matches.
	pkgIndex := make(map[string][]*inventory.Package, len(inv.Packages))
	for i := range inv.Packages {
		p := &inv.Packages[i]
		key := string(p.Ecosystem) + "|" + p.Name
		pkgIndex[key] = append(pkgIndex[key], p)
	}
	for _, inc := range d.incs {
		for _, ip := range inc.Packages {
			eco := normalizeEcosystem(ip.Ecosystem)
			key := string(eco) + "|" + ip.Name
			candidates, ok := pkgIndex[key]
			if !ok {
				continue
			}
			versionSet := make(map[string]struct{}, len(ip.Versions))
			matchAny := false
			for _, v := range ip.Versions {
				if v == "*" {
					matchAny = true
					continue
				}
				versionSet[v] = struct{}{}
			}
			for _, p := range candidates {
				if !matchAny {
					if _, ok := versionSet[p.Version]; !ok {
						continue
					}
				}
				out = append(out, findings.Finding{
					Detector:       "incident-pack",
					Category:       findings.CategorySupplyChainAttack,
					PURL:           p.PURL,
					Ecosystem:      p.Ecosystem,
					Name:           p.Name,
					Version:        p.Version,
					VulnID:         inc.ID,
					Summary:        inc.Name,
					Severity:       parseSeverity(inc.Severity),
					References:     inc.References,
					SourcePath:     p.SourcePath,
					FixUpgradeTo:   ip.SafeVersion,
					PostCompromise: inc.PostCompromise,
				})
			}
		}
	}

	// Layer 2 — file artifacts. One pass through the tree; for each visited
	// file, check every artifact glob across every incident.
	type artifactRef struct {
		Incident *incidents.Incident
		Artifact *incidents.FileArtifact
	}
	var artifacts []artifactRef
	for _, inc := range d.incs {
		for i := range inc.FileArtifacts {
			artifacts = append(artifacts, artifactRef{Incident: inc, Artifact: &inc.FileArtifacts[i]})
		}
	}
	if len(artifacts) > 0 {
		prog := progress.New(os.Stderr)
		prog.Start(fmt.Sprintf("hunting incident artifacts under %s", scanRoot))
		hitsAtStart := len(out)
		defer func() {
			hits := len(out) - hitsAtStart
			// Suppress the "complete: 0 match(es)" line — it's not
			// useful and clutters audit output when chdora walks
			// dozens of project roots that all come up clean.
			summary := ""
			if hits > 0 {
				summary = fmt.Sprintf("[chdora] artifact hunt complete: %d match(es) under %s", hits, scanRoot)
			}
			prog.Stop(summary)
		}()
		_ = filepath.WalkDir(scanRoot, func(path string, dent fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			prog.Tick()
			if dent.IsDir() {
				name := dent.Name()
				// Uses the shared inventory.ShouldSkipDir list so the
				// incident-pack file-artifact walk skips the same set
				// of dirs the inventory parser and the scan-projects
				// walker skip. Always allow the user-supplied root
				// itself (otherwise `chdora forensics --hunt-root
				// ~/testdata` would refuse to descend).
				if path != scanRoot && inventory.ShouldSkipDir(path, name) {
					return filepath.SkipDir
				}
				if _, skip := d.excludes[name]; skip {
					return filepath.SkipDir
				}
				return nil
			}
			rel, err := filepath.Rel(scanRoot, path)
			if err != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)
			for _, ar := range artifacts {
				if !globMatch(ar.Artifact.Glob, rel) {
					continue
				}
				if ar.Artifact.ContentSubstr != "" {
					content, err := os.ReadFile(path)
					if err != nil {
						continue
					}
					if !strings.Contains(string(content), ar.Artifact.ContentSubstr) {
						continue
					}
				}
				out = append(out, findings.Finding{
					Detector:       "incident-pack",
					Category:       findings.CategorySupplyChainAttack,
					VulnID:         ar.Incident.ID,
					Summary:        ar.Incident.Name + ": " + strings.TrimSpace(ar.Artifact.Description),
					Severity:       parseSeverity(ar.Artifact.Severity),
					References:     ar.Incident.References,
					SourcePath:     path,
					PostCompromise: ar.Incident.PostCompromise,
				})
				prog.Hit()
			}
			return nil
		})
	}

	return out, nil
}

// globMatch supports a small but useful subset:
//
//	"**/<path>" → match any file whose relative path ends with <path>
//	"<path>"    → path.Match (no recursive ** support)
//
// Both `pattern` and `rel` are normalized to forward slashes before matching,
// and we use `path.Match` (which always treats `/` as the separator) rather
// than `filepath.Match` (which uses `\` on Windows, so `*` would happily
// cross path separators and over-match).
func globMatch(pattern, rel string) bool {
	pattern = filepath.ToSlash(pattern)
	rel = filepath.ToSlash(rel)
	if strings.HasPrefix(pattern, "**/") {
		suffix := strings.TrimPrefix(pattern, "**/")
		return rel == suffix || strings.HasSuffix(rel, "/"+suffix)
	}
	ok, _ := path.Match(pattern, rel)
	return ok
}

func normalizeEcosystem(s string) inventory.Ecosystem {
	switch strings.ToLower(s) {
	case "npm":
		return inventory.EcosystemNPM
	case "pypi":
		return inventory.EcosystemPyPI
	case "github actions", "githubactions", "gh-actions":
		return inventory.EcosystemActions
	case "homebrew", "brew":
		return inventory.EcosystemHomebrew
	case "debian", "deb":
		return inventory.EcosystemDebian
	case "browser extension", "browserext", "browser-ext":
		return inventory.EcosystemBrowserExt
	case "ide extension", "ideext", "ide-ext":
		return inventory.EcosystemIDEExt
	case "go", "golang", "go modules":
		return inventory.EcosystemGoModules
	}
	return inventory.Ecosystem(s)
}

func parseSeverity(s string) findings.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return findings.SeverityCritical
	case "HIGH":
		return findings.SeverityHigh
	case "MEDIUM", "MODERATE":
		return findings.SeverityMedium
	case "LOW":
		return findings.SeverityLow
	}
	return findings.SeverityUnknown
}
