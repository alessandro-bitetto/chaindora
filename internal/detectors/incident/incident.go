package incident

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/incidents"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
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
//   1. Package name+version matches in the inventory.
//   2. File artifacts whose glob matches a file under scanRoot, optionally
//      gated by a content substring.
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
			for _, v := range ip.Versions {
				versionSet[v] = struct{}{}
			}
			for _, p := range candidates {
				if _, ok := versionSet[p.Version]; !ok {
					continue
				}
				out = append(out, findings.Finding{
					Detector:   "incident-pack",
					PURL:       p.PURL,
					Ecosystem:  p.Ecosystem,
					Name:       p.Name,
					Version:    p.Version,
					VulnID:     inc.ID,
					Summary:    inc.Name,
					Severity:   parseSeverity(inc.Severity),
					References: inc.References,
					SourcePath: p.SourcePath,
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
		_ = filepath.WalkDir(scanRoot, func(path string, dent fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if dent.IsDir() {
				name := dent.Name()
				if name == "node_modules" || name == ".venv" || name == "venv" || name == ".git" {
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
					Detector:   "incident-pack",
					VulnID:     ar.Incident.ID,
					Summary:    ar.Incident.Name + ": " + strings.TrimSpace(ar.Artifact.Description),
					Severity:   parseSeverity(ar.Artifact.Severity),
					References: ar.Incident.References,
					SourcePath: path,
				})
			}
			return nil
		})
	}

	return out, nil
}

// globMatch supports a small but useful subset:
//   "**/<path>" → match any file whose relative path ends with <path>
//   "<path>"    → filepath.Match (no recursive ** support)
func globMatch(pattern, rel string) bool {
	pattern = filepath.ToSlash(pattern)
	if strings.HasPrefix(pattern, "**/") {
		suffix := strings.TrimPrefix(pattern, "**/")
		return rel == suffix || strings.HasSuffix(rel, "/"+suffix)
	}
	ok, _ := filepath.Match(pattern, rel)
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
