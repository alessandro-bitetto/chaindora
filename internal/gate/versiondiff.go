package gate

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
)

// VersionBumpDiff catches the "previously clean, now malicious"
// subclass of supply-chain attack — event-stream, ua-parser-js,
// the eslint-config-prettier compromise. The pattern: a package
// has been stable, useful, and unchanged for months. Someone takes
// over the maintainer (account hijack OR voluntary handoff), then
// publishes a "minor bump" that injects malicious code.
//
// The check downloads both the version being installed AND the
// prior trusted version, runs the static scanner against each, and
// reports as Warn/Block when the new version has STATIC-PATTERN
// SIGNALS the old one didn't. We score on the DELTA, not the
// absolute count — so a package that's always had eval (a JS
// templating lib) doesn't false-positive, but the moment that
// package starts adding postinstall network calls, we catch it.
type VersionBumpDiff struct {
	Probes  *Probes
	BlockAt int
	WarnAt  int
}

// NewVersionBumpDiff returns a VersionBumpDiff with default
// thresholds. Caller populates Probes.
func NewVersionBumpDiff() *VersionBumpDiff {
	return &VersionBumpDiff{
		Probes:  NewProbes(),
		BlockAt: 3,
		WarnAt:  1,
	}
}

func (v *VersionBumpDiff) Name() string { return "version-diff" }

func (v *VersionBumpDiff) Check(ctx context.Context, ref PackageRef) CheckResult {
	r := CheckResult{Checker: v.Name()}
	probe, ok := v.Probes.versionProbeFor(ref.Ecosystem)
	if !ok {
		r.Verdict = VerdictApprove
		r.Reason = fmt.Sprintf("version-diff: no probe for ecosystem %q", ref.Ecosystem)
		return r
	}
	versions, err := probe.AllVersions(ctx, ref.Name)
	if err != nil {
		r.Verdict = VerdictUnknown
		r.Reason = fmt.Sprintf("version-timeline lookup failed: %v", err)
		return r
	}
	prior := priorVersion(versions, ref.Version)
	if prior == nil {
		// First publish — nothing to diff against. The
		// publisher-change check handles brand-new packages;
		// version-diff has nothing to contribute here.
		r.Verdict = VerdictApprove
		r.Reason = "no prior version to diff against"
		return r
	}
	// Scan both versions.
	newFindings, err := v.scanVersion(ctx, probe, ref.Name, ref.Version)
	if err != nil {
		r.Verdict = VerdictUnknown
		r.Reason = fmt.Sprintf("new-version scan failed: %v", err)
		return r
	}
	priorFindings, err := v.scanVersion(ctx, probe, ref.Name, prior.Version)
	if err != nil {
		r.Verdict = VerdictUnknown
		r.Reason = fmt.Sprintf("prior-version scan failed: %v", err)
		return r
	}
	// Score the DELTA — patterns present in the new version that
	// weren't in the prior. Identical signatures cancel out.
	newSet := patternSet(newFindings)
	priorSet := patternSet(priorFindings)
	deltaScore := 0
	var deltaPatterns []string
	for pattern, weight := range newSet {
		if priorSet[pattern] == 0 {
			deltaScore += weight
			deltaPatterns = append(deltaPatterns, pattern)
		}
	}
	if deltaScore == 0 {
		r.Verdict = VerdictApprove
		r.Reason = fmt.Sprintf("no new static-pattern signals introduced since %s", prior.Version)
		return r
	}
	sort.Strings(deltaPatterns)
	patterns := strings.Join(deltaPatterns, ", ")
	if deltaScore >= v.BlockAt {
		r.Verdict = VerdictBlock
		r.Reason = fmt.Sprintf("new suspicious patterns since %s (score %d ≥ block %d): %s",
			prior.Version, deltaScore, v.BlockAt, patterns)
		return r
	}
	r.Verdict = VerdictWarn
	r.Reason = fmt.Sprintf("new suspicious patterns since %s (score %d): %s",
		prior.Version, deltaScore, patterns)
	return r
}

// scanVersion downloads + scans one specific version's tarball.
// Returns the raw findings list. Ecosystem-agnostic: the probe
// supplies the bytes, scanTarball walks them.
func (v *VersionBumpDiff) scanVersion(ctx context.Context, probe VersionProbe, name, version string) ([]StaticFinding, error) {
	url, err := probe.TarballURL(ctx, name, version)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := probe.FetchTarball(ctx, url, &buf); err != nil {
		return nil, err
	}
	return scanTarball(buf.Bytes(), 50<<20)
}

// patternSet returns a map of pattern → weight, taking the MAX
// weight per pattern (in case the same pattern appears multiple
// times — the per-file finding doesn't double-count for diff
// purposes).
func patternSet(fs []StaticFinding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		if out[f.Pattern] < f.Weight {
			out[f.Pattern] = f.Weight
		}
	}
	return out
}
