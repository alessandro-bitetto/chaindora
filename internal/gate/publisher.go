package gate

import (
	"context"
	"fmt"

	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

// PublisherChange catches the most common shape of supply-chain
// attack: someone hijacks a maintainer's npm account (or the
// maintainer hands off the package to a stranger) and publishes a
// new version under a different publisher. event-stream, ctx,
// ua-parser-js, eslint-config-prettier — all the same pattern.
//
// The check compares the publisher of the version being installed
// against the publisher of the prior version on the timeline. If
// they differ, we Warn. We don't Block by default: legitimate
// maintainer transitions happen (corp acquisitions, project hand-
// offs to community maintainers), so the user needs the option to
// approve them. Strict policy treats Warn as Block; Lenient lets
// it through with a notice in the audit log.
//
// Network failure → Verdict=Unknown (fail-closed by default).
// Missing publisher info on either side (older publishes without
// _npmUser) → Unknown — we can't compare what we don't have.
type PublisherChange struct {
	NPM npmPublisherProbe
}

// npmPublisherProbe is the slice of registries.NPM we need.
// Interface form so tests inject deterministic data.
type npmPublisherProbe interface {
	PublisherOfVersion(ctx context.Context, name, version string) (string, error)
	AllVersions(ctx context.Context, name string) ([]registries.VersionInfo, error)
}

// NewPublisherChange returns a PublisherChange backed by the
// default public-registry NPM probe.
func NewPublisherChange() *PublisherChange {
	return &PublisherChange{NPM: registries.NewNPM()}
}

func (p *PublisherChange) Name() string { return "publisher-change" }

func (p *PublisherChange) Check(ctx context.Context, ref PackageRef) CheckResult {
	r := CheckResult{Checker: p.Name()}
	if ref.Ecosystem != "npm" {
		// PyPI tracks publishers but the metadata shape is
		// different; we'll wire it in a follow-up. Skip silently
		// here so the verdict is Approve-by-default for
		// non-npm ecosystems rather than Unknown (which would
		// fail-closed and over-block).
		r.Verdict = VerdictApprove
		r.Reason = fmt.Sprintf("publisher-change not yet wired for %q", ref.Ecosystem)
		return r
	}

	currentPublisher, err := p.NPM.PublisherOfVersion(ctx, ref.Name, ref.Version)
	if err != nil {
		r.Verdict = VerdictUnknown
		r.Reason = fmt.Sprintf("registry lookup failed: %v", err)
		return r
	}
	if currentPublisher == "" {
		r.Verdict = VerdictUnknown
		r.Reason = "registry did not report _npmUser for this version"
		return r
	}

	versions, err := p.NPM.AllVersions(ctx, ref.Name)
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
		// No prior version means this is the FIRST publish of
		// the package. We treat that as Warn — a brand-new
		// package being installed for the first time is a
		// soft sleeper-attack signal on its own. The next
		// checker layer (maintainer-trust) sharpens this with
		// account-age and publish-count.
		r.Verdict = VerdictWarn
		r.Reason = fmt.Sprintf("first-ever publish of this package (publisher: %s)", currentPublisher)
		return r
	}
	if prior.Publisher == "" {
		r.Verdict = VerdictUnknown
		r.Reason = fmt.Sprintf("prior version %s had no _npmUser — can't compare publishers", prior.Version)
		return r
	}
	if prior.Publisher != currentPublisher {
		r.Verdict = VerdictWarn
		r.Reason = fmt.Sprintf("publisher changed: %s (prior %s) → %s (this %s)",
			prior.Publisher, prior.Version, currentPublisher, ref.Version)
		r.Detail = fmt.Sprintf("Account-takeover indicator. Legitimate causes: maintainer handoff, corporate acquisition. Verify via the project's GitHub release notes or maintainer announcement before approving.")
		return r
	}
	r.Verdict = VerdictApprove
	r.Reason = fmt.Sprintf("publisher unchanged from prior version %s (%s)", prior.Version, currentPublisher)
	return r
}

// priorVersion finds the version immediately preceding `target` on
// the chronologically-sorted versions list. Returns nil if target
// is the first-ever version or not present in the list. We compare
// on Version string match (exact) rather than semver to avoid
// false negatives on packages with non-semver versioning.
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
