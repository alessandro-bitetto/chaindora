// Package predictive replays the gate's behavioral checkers against
// already-installed packages. Where the gate-mode prevents bad installs
// at the registry boundary, this detector flags installed packages
// whose registry-side signals match attack-in-progress shapes: just-
// published, publisher just changed, suspicious cross-version drift,
// content hash differs from what was previously vetted.
//
// Predictive findings are advisory by default — they emit at
// severity=medium so they don't break the default `--fail-on=critical,
// high` gate in CI. Credential collection plus outbound HTTP emits High
// severity with Medium confidence; republish-guard emits Critical for
// changed integrity observations. Findings still require contextual review.
//
// Reuses the gate's `Checker` / `Probes` infrastructure verbatim. A
// checker added to the gate stack — cooldown, publisher-change,
// maintainer-trust, version-diff, provenance — flows here too without
// per-detector wiring.
package predictive

import (
	"context"
	"strings"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/gate"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// Detector runs gate-style behavioral checks against the scan inventory.
type Detector struct {
	probes            *gate.Probes
	cooldownThreshold time.Duration
	cache             *gate.Cache
}

const IncompleteID = "CHDORA-PREDICTIVE-INCOMPLETE"

// New returns a predictive Detector wired with the given probe table,
// cooldown threshold, and (optional) verdict cache. cache can be nil —
// without it, the republish-guard signal won't fire but the other
// behavioral checks still work.
func New(probes *gate.Probes, cooldownThreshold time.Duration, cache *gate.Cache) *Detector {
	if cooldownThreshold <= 0 {
		cooldownThreshold = 72 * time.Hour
	}
	return &Detector{
		probes:            probes,
		cooldownThreshold: cooldownThreshold,
		cache:             cache,
	}
}

// Detect builds gate.PackageRefs from the inventory, runs the
// predictive checker stack, and emits actionable findings. Credential
// inspection failures are reported explicitly as configuration findings.
func (d *Detector) Detect(ctx context.Context, inv *inventory.Inventory) ([]findings.Finding, error) {
	if inv == nil || len(inv.Packages) == 0 {
		return nil, nil
	}

	// Map inventory packages to gate refs. Skip ecosystems with no
	// gate-side probe (host-forensics findings, CI YAML refs, etc.).
	refs := make([]gate.PackageRef, 0, len(inv.Packages))
	sources := make(map[string]string, len(inv.Packages))
	for _, p := range inv.Packages {
		eco := inventoryToGateEcosystem(p.Ecosystem)
		if eco == "" {
			continue
		}
		ref := gate.PackageRef{
			Ecosystem: eco,
			Name:      p.Name,
			Version:   p.Version,
			// Lockfile-recorded integrity. Empty when the
			// ecosystem's lockfile doesn't carry one — the
			// republish-guard then silently skips this package
			// (no tamper-signal possible without a hash to
			// compare against). With Integrity populated, a
			// later install of the same name@version with a
			// different hash trips the guard.
			Integrity: p.Integrity,
		}
		refs = append(refs, ref)
		// Track the source path so findings can point at the
		// lockfile that pulled the package in.
		sources[ref.String()] = p.SourcePath
	}
	if len(refs) == 0 {
		return nil, nil
	}

	checkers := d.buildCheckerStack()
	results := gate.CachedRun(ctx, checkers, refs, d.cache)

	var out []findings.Finding
	for i, pc := range results {
		invPkg := inv.Packages[lookupInventoryIndex(inv, pc.Package, i)]
		for _, r := range pc.Results {
			if r.Verdict == gate.VerdictApprove {
				continue
			}
			f := findings.Finding{
				Detector:   "predictive:" + r.Checker,
				Category:   findings.CategoryPredictive,
				Ecosystem:  invPkg.Ecosystem,
				Name:       invPkg.Name,
				Version:    invPkg.Version,
				PURL:       invPkg.PURL,
				Summary:    summaryWithDetail(r),
				Severity:   severityFor(r),
				Confidence: confidenceFor(r, &invPkg),
				SourcePath: sources[pc.Package.String()],
				// Carry the lockfile-recorded integrity so the
				// fleet server can detect cross-agent republishes
				// even when the local cache hasn't seen the prior
				// version on this machine.
				Integrity: invPkg.Integrity,
			}
			if r.Verdict == gate.VerdictUnknown {
				f.Category = findings.CategoryConfiguration
				f.VulnID = IncompleteID
				f.Summary = r.Checker + " inspection incomplete: " + f.Summary
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// buildCheckerStack assembles the predictive subset of gate checkers.
// Version-diff detects changes; a targeted credential scan also catches
// suspicious npm/PyPI artifacts with no prior version or no pattern delta.
// Generic eval/obfuscation findings stay on the version-diff path.
func (d *Detector) buildCheckerStack() []gate.Checker {
	cooldown := gate.NewCooldown(d.cooldownThreshold)
	cooldown.Probes = d.probes

	pub := gate.NewPublisherChange()
	pub.Probes = d.probes

	maint := gate.NewMaintainerTrust()
	maint.Probes = d.probes

	prov := gate.NewProvenanceCheck()
	prov.Probes = d.probes

	vd := gate.NewVersionBumpDiff()
	vd.Probes = d.probes

	secrets := gate.NewStaticScan()
	secrets.Probes = d.probes
	secrets.CredentialsOnly = true
	return []gate.Checker{cooldown, pub, maint, prov, vd, secrets}
}

// summaryWithDetail folds the CheckResult's Detail lines into the
// Finding summary so the renderer (which has no Detail field of its
// own) can still surface the actionable bits. Without this,
// maintainer-trust renders as a bare "1 soft trust signal(s)" — the
// underlying "190-day dormancy before this bump" lives only in
// Detail and never reaches the user at scan time.
func summaryWithDetail(r gate.CheckResult) string {
	detail := strings.TrimSpace(r.Detail)
	if detail == "" {
		return r.Reason
	}
	// Detail is multi-line bulleted in maintainer-trust; collapse
	// into a single line so the scan renderer (one-line summary
	// per finding) keeps a tidy layout.
	detail = strings.ReplaceAll(detail, "\n", "; ")
	detail = strings.TrimPrefix(detail, "- ")
	detail = strings.TrimPrefix(detail, "  - ")
	return r.Reason + " — " + detail
}

// severityFor maps a CheckResult to a Finding severity for the
// predictive detector. per-checker tuning so the noisier
// behavioral signals (publisher-change, maintainer-trust,
// provenance) emit at LOW instead of MEDIUM. They're advisory
// even at the gate; the scan-time replay produces orders of
// magnitude more of them — a $HOME audit easily emits thousands
// from organic team-rotation / single-utility-version noise.
// Keeping them at Low lets users still see them when hunting
// incidents while staying out of `--fail-on=medium` CI gates.
//
//   - credential-exfiltration → High (reviewable source heuristic)
//   - republish-guard → Critical (hard tamper signal)
//   - cooldown        → Medium (time-sensitive: freshly published)
//   - version-diff    → Medium (cross-version behavioral change)
//   - publisher-change, maintainer-trust, provenance → Low
//   - Verdict=Unknown → Low (registry probe couldn't run)
func severityFor(r gate.CheckResult) findings.Severity {
	switch r.Checker {
	case "credential-exfiltration":
		if r.Verdict == gate.VerdictUnknown {
			return findings.SeverityLow
		}
		return findings.SeverityHigh
	case "republish-guard":
		return findings.SeverityCritical
	case "cooldown", "version-diff":
		if r.Verdict == gate.VerdictUnknown {
			return findings.SeverityLow
		}
		return findings.SeverityMedium
	case "publisher-change", "maintainer-trust", "provenance":
		return findings.SeverityLow
	}
	if r.Verdict == gate.VerdictUnknown {
		return findings.SeverityLow
	}
	return findings.SeverityMedium
}

// confidenceFor reports the detector's certainty for a predictive
// finding. The mapping mirrors severityFor's logic:
//
//   - republish-guard with a non-empty integrity → High. Same
//     (name, version) reappearing with different bytes is a hard
//     tamper signal; the evidence is the hash divergence itself.
//   - cooldown / version-diff → Medium. The behavioral signal is
//     concrete (registry timestamps, scored pattern delta) but
//     interpretation depends on context (a brand-new package vs
//     a maintainer's normal cadence).
//   - publisher-change / maintainer-trust / provenance → Low. These
//     are soft signals — high false-positive rate from organic
//     maintainer churn — and emit at Low severity for the same
//     reason. Surfaced for hunting, not gating.
//   - Verdict=Unknown → Low. Anything the probe couldn't actually
//     check shouldn't claim certainty.
//
// Empty Integrity downgrades republish-guard to Medium since we
// don't have the canonical evidence to back the claim.
func confidenceFor(r gate.CheckResult, pkg *inventory.Package) findings.Confidence {
	if r.Verdict == gate.VerdictUnknown {
		return findings.ConfidenceLow
	}
	switch r.Checker {
	case "republish-guard":
		if pkg != nil && pkg.Integrity != "" {
			return findings.ConfidenceHigh
		}
		return findings.ConfidenceMedium
	case "cooldown", "version-diff":
		return findings.ConfidenceMedium
	case "publisher-change", "maintainer-trust", "provenance":
		return findings.ConfidenceLow
	}
	return findings.ConfidenceMedium
}

// inventoryToGateEcosystem maps the inventory's ecosystem strings
// (capitalized — "PyPI", "NuGet") to the gate's lowercase keys
// ("pypi", "nuget") used in the Probes map.
func inventoryToGateEcosystem(eco inventory.Ecosystem) string {
	switch eco {
	case inventory.EcosystemNPM:
		return "npm"
	case inventory.EcosystemPyPI:
		return "pypi"
	case inventory.EcosystemCrates:
		return "crates"
	case inventory.EcosystemGoModules:
		return "go"
	case inventory.EcosystemNuGet:
		return "nuget"
	}
	return ""
}

// lookupInventoryIndex finds the inventory.Package whose
// (ecosystem, name, version) matches a gate.PackageRef. Used to
// recover the SourcePath / PURL for emitted findings. Falls back
// to the position-aligned index when ordering is stable (the
// common case — CachedRun preserves input order).
func lookupInventoryIndex(inv *inventory.Inventory, ref gate.PackageRef, hint int) int {
	if hint >= 0 && hint < len(inv.Packages) {
		p := &inv.Packages[hint]
		if p.Name == ref.Name && p.Version == ref.Version {
			return hint
		}
	}
	for i := range inv.Packages {
		p := &inv.Packages[i]
		if p.Name == ref.Name && p.Version == ref.Version &&
			strings.EqualFold(string(p.Ecosystem), ref.Ecosystem) {
			return i
		}
	}
	return 0
}
