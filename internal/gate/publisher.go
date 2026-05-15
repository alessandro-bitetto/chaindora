package gate

import (
	"context"
	"fmt"

	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

// PublisherChange catches the most common shape of supply-chain
// attack: someone hijacks a maintainer's account (or the
// maintainer hands off the package to a stranger) and publishes
// a new version under a different publisher. event-stream, ctx,
// ua-parser-js, eslint-config-prettier — all the same pattern.
//
// The check compares the publisher of the version being installed
// against the publisher of the prior version on the timeline. If
// they differ, we Warn — not Block. Legitimate maintainer
// transitions happen (corp acquisitions, project handoffs); the
// user needs the option to approve them. Strict policy treats
// Warn as Block.
//
// Per-ecosystem semantics:
//   - npm:      _npmUser per version is reliably reported
//   - PyPI:     no per-version publisher in the public API;
//               we degrade to comparing project-level
//               maintainer_email across versions when available,
//               return Unknown otherwise
//   - RubyGems: rubygems.org/api/v1/gems/X/owners.json (project-
//               level owner list)
//   - crates:   crates.io/api/v1/crates/X/owners (project-level)
//   - Maven:    POM `developers` block (heterogeneous; degrades
//               often)
type PublisherChange struct {
	Probes *Probes
}

// NewPublisherChange returns a PublisherChange with an empty
// probe table. Callers populate Probes before adding to the
// checker stack.
func NewPublisherChange() *PublisherChange {
	return &PublisherChange{Probes: NewProbes()}
}

func (p *PublisherChange) Name() string { return "publisher-change" }

func (p *PublisherChange) Check(ctx context.Context, ref PackageRef) CheckResult {
	r := CheckResult{Checker: p.Name()}
	probe, ok := p.Probes.versionProbeFor(ref.Ecosystem)
	if !ok {
		r.Verdict = VerdictApprove
		r.Reason = fmt.Sprintf("publisher-change: no probe for ecosystem %q (signal-free passthrough)", ref.Ecosystem)
		return r
	}

	currentPublisher, err := probe.PublisherOfVersion(ctx, ref.Name, ref.Version)
	if err != nil {
		r.Verdict = VerdictUnknown
		r.Reason = fmt.Sprintf("registry lookup failed: %v", err)
		return r
	}
	if currentPublisher == "" {
		r.Verdict = VerdictUnknown
		r.Reason = "registry did not report a publisher for this version"
		return r
	}

	versions, err := probe.AllVersions(ctx, ref.Name)
	if err != nil {
		r.Verdict = VerdictUnknown
		r.Reason = fmt.Sprintf("version-timeline lookup failed: %v", err)
		return r
	}
	if len(versions) == 0 {
		r.Verdict = VerdictUnknown
		r.Reason = "registry returned no version timeline"
		return r
	}

	prior := priorVersion(versions, ref.Version)
	if prior == nil {
		// First publish — Warn (brand-new-package signal). The
		// next checker (maintainer-trust) sharpens this with
		// account-age and publish-count.
		r.Verdict = VerdictWarn
		r.Reason = fmt.Sprintf("first-ever publish of this package (publisher: %s)", currentPublisher)
		return r
	}
	if prior.Publisher == "" {
		r.Verdict = VerdictUnknown
		r.Reason = fmt.Sprintf("prior version %s had no publisher metadata — can't compare", prior.Version)
		return r
	}
	if prior.Publisher != currentPublisher {
		r.Verdict = VerdictWarn
		r.Reason = fmt.Sprintf("publisher changed: %s (prior %s) → %s (this %s)",
			prior.Publisher, prior.Version, currentPublisher, ref.Version)
		r.Detail = "Account-takeover indicator. Legitimate causes: maintainer handoff, corporate acquisition. Verify via the project's release notes or maintainer announcement before approving."
		return r
	}
	r.Verdict = VerdictApprove
	r.Reason = fmt.Sprintf("publisher unchanged from prior version %s (%s)", prior.Version, currentPublisher)
	return r
}

// priorVersion finds the version immediately preceding `target`
// on the chronologically-sorted versions list. Returns nil if
// target is the first-ever version or not present in the list.
func priorVersion(versions []registries.VersionInfo, target string) *registries.VersionInfo {
	idx := -1
	for i, v := range versions {
		if v.Version == target {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return nil
	}
	return &versions[idx-1]
}
