package gate

import (
	"context"
	"fmt"
	"time"
)

// MaintainerTrust adds auxiliary trust signals about the publisher
// of a (pkg, version). Where publisher-change catches takeovers
// across versions, maintainer-trust catches red flags about the
// publisher account itself:
//
//   - package is brand new (< NewPackageDays since first publish)
//   - very few versions ever published (< MinVersionCount)
//   - long activity gap then sudden burst (> GapThreshold) — the
//     classic sleeper-revival pattern
//
// Composite trust score: each signal contributes 1 point.
// Threshold 1+ → Warn (combined with other checkers easily
// blocks). No Block from this checker alone — these are soft
// signals.
//
// Per-ecosystem semantics: any VersionProbe that returns a
// non-empty AllVersions list with PublishedAt timestamps will
// produce useful signals here. Cross-ecosystem by design.
type MaintainerTrust struct {
	Probes          *Probes
	NewPackageDays  int           // < this since first publish → Warn
	MinVersionCount int           // < this total versions → Warn
	GapThreshold    time.Duration // gap of this long before bump → Warn
}

// NewMaintainerTrust returns a MaintainerTrust with default
// thresholds (30 days, 3 versions, 6 months gap).
func NewMaintainerTrust() *MaintainerTrust {
	return &MaintainerTrust{
		Probes:          NewProbes(),
		NewPackageDays:  30,
		MinVersionCount: 3,
		GapThreshold:    6 * 30 * 24 * time.Hour,
	}
}

func (m *MaintainerTrust) Name() string { return "maintainer-trust" }

func (m *MaintainerTrust) Check(ctx context.Context, ref PackageRef) CheckResult {
	r := CheckResult{Checker: m.Name()}
	probe, ok := m.Probes.versionProbeFor(ref.Ecosystem)
	if !ok {
		r.Verdict = VerdictApprove
		r.Reason = fmt.Sprintf("maintainer-trust: no probe for ecosystem %q", ref.Ecosystem)
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

	// Signal 3: long dormancy then sudden bump.
	if prior := priorVersion(versions, ref.Version); prior != nil {
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
	for i, s := range signals {
		if i > 0 {
			r.Detail += "\n"
		}
		r.Detail += "  - " + s
	}
	return r
}
