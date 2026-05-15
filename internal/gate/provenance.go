package gate

import (
	"context"
	"fmt"

	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

// ProvenanceCheck flags packages that lack a sigstore-backed
// provenance attestation. npm has supported `npm publish
// --provenance` since 9.5, and adoption is rising but still
// optional — so a blanket "block on no provenance" would be far
// too noisy.
//
// The default policy: warn only when ANOTHER version of the
// same package has provenance. That isolates the high-value
// signal — "this publisher started using provenance, then
// stopped" — which is a strong account-takeover indicator on
// par with the publisher-change check. Bare absence on packages
// that have never had provenance returns Approve (passthrough).
//
// Strict mode (Require=true) blocks any version without
// provenance regardless of history; suitable for "we only want
// audited supply chain" projects.
type ProvenanceCheck struct {
	NPM     provenanceProbe
	Require bool // strict mode: refuse anything without provenance
}

// provenanceProbe is the subset of registries.NPM we need.
type provenanceProbe interface {
	HasProvenance(ctx context.Context, name, version string) (bool, error)
	AnyVersionHasProvenance(ctx context.Context, name string) (bool, error)
}

// NewProvenanceCheck returns a ProvenanceCheck with the default
// "warn only when a publisher started using provenance and
// dropped it" policy.
func NewProvenanceCheck() *ProvenanceCheck {
	return &ProvenanceCheck{NPM: registries.NewNPM(), Require: false}
}

func (p *ProvenanceCheck) Name() string { return "provenance" }

func (p *ProvenanceCheck) Check(ctx context.Context, ref PackageRef) CheckResult {
	r := CheckResult{Checker: p.Name()}
	if ref.Ecosystem != "npm" {
		// PyPI's trusted-publisher equivalent is shaped
		// differently (per-publisher OIDC); v0.10 wires npm
		// only.
		r.Verdict = VerdictApprove
		r.Reason = fmt.Sprintf("provenance not yet wired for %q", ref.Ecosystem)
		return r
	}
	hasProv, err := p.NPM.HasProvenance(ctx, ref.Name, ref.Version)
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
	// No provenance on this version. Decide based on policy.
	if p.Require {
		r.Verdict = VerdictBlock
		r.Reason = "no sigstore provenance and --require-provenance is set"
		return r
	}
	// Default mode: only warn if SOME version of this package
	// has provenance — i.e. the publisher knows how, but didn't
	// for this version.
	anyHas, err := p.NPM.AnyVersionHasProvenance(ctx, ref.Name)
	if err != nil {
		r.Verdict = VerdictUnknown
		r.Reason = fmt.Sprintf("provenance-history lookup failed: %v", err)
		return r
	}
	if anyHas {
		r.Verdict = VerdictWarn
		r.Reason = "no sigstore provenance on this version, but other versions of this package have it — possible regression / takeover signal"
		return r
	}
	r.Verdict = VerdictApprove
	r.Reason = "no sigstore provenance (publisher has never used it; not a signal by itself)"
	return r
}
