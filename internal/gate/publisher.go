package gate

import (
	"context"
	"fmt"
	"strings"

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

// priorVersion finds the most recent version published before `target`
// in the same major release line. Returns nil if target is the
// first-ever version or not present in the list.
//
// Packages routinely maintain parallel LTS branches — Angular 18.x and
// 19.x, React 17.x and 18.x, Node.js LTS, Babel betas — where the
// chronologically-adjacent version often belongs to a different
// release line and has no semantic relationship to `target`. A purely
// chronological prior would systematically surface spurious
// "publisher changed" / "new patterns" signals every time an LTS
// release happens between two current-branch releases.
//
// Scoping to the same major fixes this. When no same-major prior
// exists (a legitimate major-version bump like 5.0.0 after 4.20.0),
// we fall back to the chronologically-preceding version so the
// publisher-change / version-diff signals still cover real
// maintainer transitions across majors.
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
	if key := majorKey(target); key != "" {
		for i := idx - 1; i >= 0; i-- {
			if majorKey(versions[i].Version) == key {
				return &versions[i]
			}
		}
	}
	return &versions[idx-1]
}

// majorKey returns a coarse "release line" identifier from a version
// string. Used to scope priorVersion to same-major comparisons.
//
//	"1.2.3"        → "1"
//	"18.2.14"      → "18"
//	"1.0.0-rc.1"   → "1"
//	"v1.2.3"       → "1"      (Go module style)
//	"0.5.2"        → "0.5"    (semver: 0.minor bumps are breaking,
//	                           so 0.5.x and 0.6.x are different lines)
//
// Returns "" for versions that don't start with a numeric major
// segment; the caller then falls back to the chronological prior.
func majorKey(v string) string {
	if v == "" {
		return ""
	}
	parts := strings.SplitN(v, ".", 3)
	head := strings.TrimPrefix(parts[0], "v")
	if !isASCIIDigits(head) {
		return ""
	}
	if head == "0" && len(parts) >= 2 {
		next := parts[1]
		end := 0
		for end < len(next) && next[end] >= '0' && next[end] <= '9' {
			end++
		}
		if end > 0 {
			return "0." + next[:end]
		}
	}
	return head
}

func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
