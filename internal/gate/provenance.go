package gate

import (
	"context"
	"fmt"
)

// ProvenanceCheck flags packages that lack a sigstore-backed
// provenance attestation. npm has supported `npm publish
// --provenance` since 9.5, and adoption is rising but still
// optional — so a blanket "block on no provenance" would be far
// too noisy.
//
// The default policy: warn only when ANOTHER version of the same
// package has provenance. That isolates the high-value signal —
// "this publisher started using provenance, then stopped" —
// which is a strong account-takeover indicator on par with the
// publisher-change check. Bare absence on packages that have
// never had provenance returns Approve (passthrough).
//
// Strict mode (Require=true) blocks any version without
// provenance regardless of history.
//
// Per-ecosystem semantics: only npm exposes the attestation
// metadata today via dist.attestations. Other ecosystems return
// Approve passthrough until they have their own provenance-probe
// implementation (PyPI's trusted-publishers is shaped
// differently and would need a separate model).
type ProvenanceCheck struct {
	Probes  *Probes
	Require bool // strict mode: refuse anything without provenance
}

// NewProvenanceCheck returns a ProvenanceCheck with the default
// "warn only on regression" policy.
func NewProvenanceCheck() *ProvenanceCheck {
	return &ProvenanceCheck{Probes: NewProbes(), Require: false}
}

func (p *ProvenanceCheck) Name() string { return "provenance" }

func (p *ProvenanceCheck) Check(ctx context.Context, ref PackageRef) CheckResult {
	r := CheckResult{Checker: p.Name()}
	probe, ok := p.Probes.provenanceProbeFor(ref.Ecosystem)
	if !ok {
		r.Verdict = VerdictApprove
		r.Reason = fmt.Sprintf("provenance: no probe for ecosystem %q", ref.Ecosystem)
		return r
	}
	hasProv, err := probe.HasProvenance(ctx, ref.Name, ref.Version)
	if err != nil {
		r.Verdict = VerdictUnknown
		r.Reason = fmt.Sprintf("provenance lookup failed: %v", err)
		return r
	}
	if hasProv {
		r.Verdict = VerdictApprove
		r.Reason = "sigstore provenance present"
		return r
	}
	if p.Require {
		r.Verdict = VerdictBlock
		r.Reason = "no sigstore provenance and --require-provenance is set"
		return r
	}
	// v0.15.2 tuning: don't flag "your old version predates the
	// publisher's provenance adoption" as a regression. That was
	// the majority of false positives in scan-time replays — a
	// user has lodash@4.17.21 (3 years old, no attestation) while
	// lodash@5.x publishes WITH attestation. Not a regression,
	// just an outdated install. Real regression = LATEST published
	// version doesn't have it AND a past version did.
	if latestProbe, ok := probe.(interface {
		LatestVersionHasProvenance(context.Context, string) (bool, error)
	}); ok {
		latestHas, lerr := latestProbe.LatestVersionHasProvenance(ctx, ref.Name)
		if lerr == nil && latestHas {
			r.Verdict = VerdictApprove
			r.Reason = "no provenance on this version, but the package's latest version has it — outdated install, not a regression"
			return r
		}
	}
	anyHas, err := probe.AnyVersionHasProvenance(ctx, ref.Name)
	if err != nil {
		r.Verdict = VerdictUnknown
		r.Reason = fmt.Sprintf("provenance-history lookup failed: %v", err)
		return r
	}
	if anyHas {
		r.Verdict = VerdictWarn
		r.Reason = "real regression: latest version of this package no longer has provenance, but past versions did — possible maintainer takeover or pipeline change"
		return r
	}
	r.Verdict = VerdictApprove
	r.Reason = "no sigstore provenance (publisher has never used it; not a signal by itself)"
	return r
}
