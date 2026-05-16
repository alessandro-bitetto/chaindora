// Package predictive replays the gate's behavioral checkers against
// already-installed packages. Where the gate-mode prevents bad installs
// at the registry boundary, this detector flags installed packages
// whose registry-side signals match attack-in-progress shapes: just-
// published, publisher just changed, suspicious cross-version drift,
// content hash differs from what was previously vetted.
//
// Predictive findings are advisory by default — they emit at
// severity=medium so they don't break the default `--fail-on=critical,
// high` gate in CI. Only the integrity-based republish-guard escalates
// to critical, because a known name@version reappearing with different
// bytes is a hard tamper signal regardless of context.
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
// predictive checker stack, and emits one Finding per non-Approve
// CheckResult.
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

	// Backfill integrity for ecosystems whose lockfile doesn't
	// carry per-package hashes. rubygems (Gemfile.lock) and maven
	// (pom.xml) are the two that need a registry round-trip. The
	// existing v0.14 fetchers handle bounded-pool concurrency +
	// graceful failure. Without this, predictive's republish-guard
	// can't fire for those two ecosystems — the cache key needs a
	// non-empty Integrity to be useful.
	refs = gate.EnrichRubyGemsIntegrity(ctx, refs)
	refs = gate.EnrichMavenIntegrity(ctx, refs)

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
				Summary:    r.Reason,
				Severity:   severityFor(r),
				SourcePath: sources[pc.Package.String()],
				// Carry the lockfile-recorded integrity so the
				// fleet server can detect cross-agent republishes
				// even when the local cache hasn't seen the prior
				// version on this machine.
				Integrity: invPkg.Integrity,
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// buildCheckerStack assembles the predictive subset of the gate's
// checkers. Static-pattern is deliberately omitted from the default
// — at scan time the relevant signal is "this version's pattern
// score is anomalous vs prior versions", which version-diff captures
// without paying the tarball-download cost on every package.
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

	return []gate.Checker{cooldown, pub, maint, prov, vd}
}

// severityFor maps a CheckResult to a Finding severity for the
// predictive detector. Behavioral signals (cooldown, publisher
// churn, maintainer-trust, version drift, provenance) are
// inherently advisory at scan time — the user has already
// installed, so the value is "be aware, double-check before
// trusting" rather than "block this install." They emit at
// medium so the default --fail-on=critical,high CI gate stays
// quiet; users who want predictive signals to break the build
// can add --fail-on=critical,high,medium.
//
// republish-guard is the one exception. A known name@version
// reappearing with different bytes is a hard tamper signal
// regardless of where it fires, so it escalates to critical.
func severityFor(r gate.CheckResult) findings.Severity {
	if r.Checker == "republish-guard" {
		return findings.SeverityCritical
	}
	if r.Verdict == gate.VerdictUnknown {
		return findings.SeverityLow
	}
	return findings.SeverityMedium
}

// inventoryToGateEcosystem maps the inventory's ecosystem strings
// (capitalized — "PyPI", "RubyGems") to the gate's lowercase keys
// ("pypi", "rubygems") used in the Probes map.
func inventoryToGateEcosystem(eco inventory.Ecosystem) string {
	switch eco {
	case inventory.EcosystemNPM:
		return "npm"
	case inventory.EcosystemPyPI:
		return "pypi"
	case inventory.EcosystemRubyGems:
		return "rubygems"
	case inventory.EcosystemCrates:
		return "crates"
	case inventory.EcosystemMavenCentral:
		return "maven"
	case inventory.EcosystemGoModules:
		return "go"
	case inventory.EcosystemNuGet:
		return "nuget"
	case inventory.EcosystemPackagist:
		return "packagist"
	case inventory.EcosystemPub:
		return "pub"
	case inventory.EcosystemHex:
		return "hex"
	case inventory.EcosystemSwift:
		return "swift"
	case inventory.EcosystemHackage:
		return "hackage"
	case inventory.EcosystemCRAN:
		return "cran"
	case inventory.EcosystemJulia:
		return "julia"
	case inventory.EcosystemConda:
		return "conda"
	case inventory.EcosystemConan:
		return "conan"
	case inventory.EcosystemVcpkg:
		return "vcpkg"
	case inventory.EcosystemOpam:
		return "opam"
	case inventory.EcosystemCocoaPods:
		return "cocoapods"
	case inventory.EcosystemCarthage:
		return "carthage"
	case inventory.EcosystemCPAN:
		return "cpan"
	case inventory.EcosystemLuaRocks:
		return "luarocks"
	case inventory.EcosystemNimble:
		return "nimble"
	case inventory.EcosystemShards:
		return "shards"
	case inventory.EcosystemZig:
		return "zig"
	case inventory.EcosystemElm:
		return "elm"
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
