package osvioc

import (
	"context"
	"strings"
	"sync"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
	"github.com/alessandro-bitetto/chaindora/internal/osv"
)

type Detector struct {
	client *osv.Client
}

func New(client *osv.Client) *Detector {
	return &Detector{client: client}
}

// Detect batches the inventory against OSV.dev, hydrates each unique vuln ID,
// and emits one Finding per (package, vuln) pair.
func (d *Detector) Detect(ctx context.Context, inv *inventory.Inventory) ([]findings.Finding, error) {
	if inv == nil || len(inv.Packages) == 0 {
		return nil, nil
	}

	queries := make([]osv.Query, 0, len(inv.Packages))
	pkgRefs := make([]*inventory.Package, 0, len(inv.Packages))
	for i := range inv.Packages {
		p := &inv.Packages[i]
		eco := osvEcosystem(p.Ecosystem)
		if eco == "" {
			continue
		}
		queries = append(queries, osv.Query{
			Package: osv.QueryPackage{Name: p.Name, Ecosystem: eco},
			Version: p.Version,
		})
		pkgRefs = append(pkgRefs, p)
	}
	if len(queries) == 0 {
		return nil, nil
	}

	results, err := d.client.QueryBatch(ctx, queries)
	if err != nil {
		return nil, err
	}

	idSet := map[string]struct{}{}
	for _, r := range results {
		for _, v := range r.Vulns {
			idSet[v.ID] = struct{}{}
		}
	}

	hydrated := make(map[string]*osv.Vulnerability, len(idSet))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for id := range idSet {
		id := id
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			v, err := d.client.GetVuln(ctx, id)
			if err != nil || v == nil {
				return
			}
			mu.Lock()
			hydrated[id] = v
			mu.Unlock()
		}()
	}
	wg.Wait()

	var out []findings.Finding
	for i, r := range results {
		if i >= len(pkgRefs) {
			break
		}
		p := pkgRefs[i]
		for _, vr := range r.Vulns {
			f := findings.Finding{
				Detector:   "osv-ioc",
				Category:   categoryForOSVID(vr.ID),
				PURL:       p.PURL,
				Ecosystem:  p.Ecosystem,
				Name:       p.Name,
				Version:    p.Version,
				VulnID:     vr.ID,
				Severity:   findings.SeverityUnknown,
				SourcePath: p.SourcePath,
			}
			if v, ok := hydrated[vr.ID]; ok {
				f.Summary = v.Summary
				if f.Summary == "" {
					f.Summary = firstLine(v.Details)
				}
				f.Severity = severityFromVuln(v)
				for _, ref := range v.References {
					f.References = append(f.References, ref.URL)
				}
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// categoryForOSVID classifies an OSV vulnerability ID into a chdora
// Category. MAL-* records come from the OpenSSF Malicious Packages
// database (federated into OSV.dev) — those are deliberate supply-chain
// attacks. Everything else (CVE-, GHSA-, PYSEC-, RUSTSEC-, ...) is a
// honest-bug dependency vulnerability.
func categoryForOSVID(id string) findings.Category {
	if strings.HasPrefix(id, "MAL-") {
		return findings.CategorySupplyChainAttack
	}
	return findings.CategoryDependencyCVE
}

func osvEcosystem(e inventory.Ecosystem) string {
	switch e {
	case inventory.EcosystemNPM:
		return "npm"
	case inventory.EcosystemPyPI:
		return "PyPI"
	case inventory.EcosystemGoModules:
		return "Go"
	}
	// Docker images: OSV's container-image story uses per-registry ecosystem
	// names (e.g. "OCI:gcr.io/distroless") and the bare "OCI" form is
	// rejected as Invalid. We skip OSV queries for EcosystemDocker until
	// we can resolve a registry-aware mapping (v0.5).
	//
	// GitHub Actions / GitLab CI / Bitbucket / CircleCI / Azure, Homebrew,
	// Debian, browser & IDE extensions are not OSV ecosystems; findings flow
	// through the incident pack and (where relevant) heuristics.
	return ""
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

func severityFromVuln(v *osv.Vulnerability) findings.Severity {
	if v == nil {
		return findings.SeverityUnknown
	}
	switch osv.HighestSeverityFromVulns(v.Severity) {
	case "CRITICAL":
		return findings.SeverityCritical
	case "HIGH":
		return findings.SeverityHigh
	case "MEDIUM":
		return findings.SeverityMedium
	case "LOW":
		return findings.SeverityLow
	}
	return findings.SeverityUnknown
}
