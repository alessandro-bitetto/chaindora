package gate

import (
	"context"
	"fmt"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

// MaintainerTrust adds auxiliary trust signals about the maintainer
// behind a (pkg, version). Where publisher-change catches account
// takeovers across versions, maintainer-trust catches red flags
// about the publisher account itself:
//
//   - package is brand new (< 30 days since first publish on the
//     registry — even legitimate new packages need warming-up time
//     before they're broadly trusted)
//   - very few versions ever published (< 3) — first-time
//     contributors are statistically more likely to have shipped
//     unintentional bugs or be sleeper accounts
//   - long activity gap then sudden burst — 6+ months silent then a
//     new version is a classic takeover signal
//
// We don't have full npm-user-profile access without authenticated
// queries, so this checker stays within the public package-doc data:
// time["created"], time["modified"], the per-version publish timeline.
// That's enough for the three signals above; richer maintainer
// metadata (account age, total packages published) is a follow-up.
//
// Composite trust score: each signal contributes 1 point. Threshold
// 1+ → Warn (combined with other checkers easily blocks). No Block
// from this checker alone — these are SOFT signals.
type MaintainerTrust struct {
	NPM             maintainerProbe
	NewPackageDays  int           // < this since first publish → Warn
	MinVersionCount int           // < this total versions → Warn
	GapThreshold    time.Duration // gap of this long before bump → Warn
}

type maintainerProbe interface {
	AllVersions(ctx context.Context, name string) ([]registries.VersionInfo, error)
}

// NewMaintainerTrust returns a MaintainerTrust with the default
// thresholds (30 days, 3 versions, 6 months gap).
func NewMaintainerTrust() *MaintainerTrust {
	return &MaintainerTrust{
		NPM:             registries.NewNPM(),
		NewPackageDays:  30,
		MinVersionCount: 3,
		GapThreshold:    6 * 30 * 24 * time.Hour,
	}
}

func (m *MaintainerTrust) Name() string { return "maintainer-trust" }

func (m *MaintainerTrust) Check(ctx context.Context, ref PackageRef) CheckResult {
	r := CheckResult{Checker: m.Name()}
	if ref.Ecosystem != "npm" {
		r.Verdict = VerdictApprove
		r.Reason = fmt.Sprintf("maintainer-trust not yet wired for %q", ref.Ecosystem)
		return r
	}
	versions, err := m.NPM.AllVersions(ctx, ref.Name)
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

	var signals []string
	now := time.Now()

	// Signal 1: brand-new package overall.
	firstPublish := versions[0].PublishedAt
	if !firstPublish.IsZero() {
		ageDays := int(now.Sub(firstPublish).Hours() / 24)
		if ageDays < m.NewPackageDays {
			signals = append(signals, fmt.Sprintf("brand-new package (first publish %d days ago)", ageDays))
		}
	}

	// Signal 2: very few versions.
	if len(versions) < m.MinVersionCount {
		signals = append(signals, fmt.Sprintf("only %d total version(s) ever published (threshold %d)",
			len(versions), m.MinVersionCount))
	}

	// Signal 3: long dormancy then sudden bump. Compare the gap
	// between the requested version and its prior — if huge,
	// that's the "sleeper revived" pattern.
	if prior := priorVersion(versions, ref.Version); prior != nil {
		// Find the requested version's publish date.
		var thisPublish time.Time
		for _, v := range versions {
			if v.Version == ref.Version {
				thisPublish = v.PublishedAt
				break
			}
		}
		if !thisPublish.IsZero() && !prior.PublishedAt.IsZero() {
			gap := thisPublish.Sub(prior.PublishedAt)
			if gap > m.GapThreshold {
				gapDays := int(gap.Hours() / 24)
				signals = append(signals, fmt.Sprintf("%d-day dormancy before this bump (prior %s, threshold %dd)",
					gapDays, prior.Version, int(m.GapThreshold.Hours()/24)))
			}
		}
	}

	if len(signals) == 0 {
		r.Verdict = VerdictApprove
		r.Reason = fmt.Sprintf("maintainer trust ok (%d versions, first publish %s ago)",
			len(versions), humanDuration(now.Sub(firstPublish)))
		return r
	}
	r.Verdict = VerdictWarn
	r.Reason = fmt.Sprintf("%d soft trust signal(s)", len(signals))
	r.Detail = ""
	for i, s := range signals {
		if i > 0 {
			r.Detail += "\n"
		}
		r.Detail += "  - " + s
	}
	return r
}
