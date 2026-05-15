// Package gate is the install-time supply-chain attack prevention layer
// for chaindora — the "shift left" complement to the post-install
// scanners. Where the rest of chdora answers "what's compromised on
// this machine right now?", `gate` answers "should this install be
// allowed to happen at all?".
//
// The gate sits between the user's intent (`npm install lodash`) and
// the registry's response. Each requested package — plus every
// transitive dependency in the resolved tree — runs through a stack
// of independent Checker implementations. Each Checker returns a
// Verdict; the package's Decision is the worst Verdict across its
// checkers. The gate as a whole approves the install only if every
// package's Decision is Approve.
//
// Fail-closed by design: any check that can't run (network down,
// registry timeout, unparseable response) returns Verdict=Unknown
// which is treated as Block in the default policy. Detection tools
// fail open; a prevention tool must fail closed.
package gate

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Verdict is one Checker's per-package opinion. The aggregator picks
// the highest-severity Verdict across checkers as the package's
// Decision; the gate as a whole rejects the install if any package
// has Decision != Approve.
type Verdict int

const (
	// VerdictUnknown — the check couldn't run (registry timeout,
	// unparseable response, missing input). Treated as Block under
	// the default fail-closed policy.
	VerdictUnknown Verdict = iota
	// VerdictApprove — the check completed and found no problem.
	VerdictApprove
	// VerdictWarn — suspicious but not unambiguously malicious; the
	// default policy allows install with a notice, a stricter
	// policy treats it as Block.
	VerdictWarn
	// VerdictBlock — unambiguously bad (known-malicious, fresh
	// publish from a different account, etc.). Install is refused.
	VerdictBlock
)

func (v Verdict) String() string {
	switch v {
	case VerdictApprove:
		return "approve"
	case VerdictWarn:
		return "warn"
	case VerdictBlock:
		return "block"
	}
	return "unknown"
}

// CheckResult is one Checker's report on one package. Reason is the
// one-line explanation the user sees ("published 14 min ago, below
// cooldown threshold 72h"). Detail is optional multi-line context
// (the obfuscated string that triggered the static-scan check, the
// publisher's account name and creation date, etc.) — surfaced when
// the user asks `--explain`.
type CheckResult struct {
	Checker string  `json:"checker"`
	Verdict Verdict `json:"verdict"`
	Reason  string  `json:"reason"`
	Detail  string  `json:"detail,omitempty"`
}

// PackageRef identifies one (ecosystem, name, version) tuple — the
// fundamental unit of work the gate operates over. Direct=true
// marks packages the user explicitly asked to install; transitives
// are Direct=false. We keep both because the policy treats them
// the same by default but tighter policies may relax checks on
// transitives (the user can't realistically vet 700 transitive
// deps by hand).
type PackageRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Direct    bool   `json:"direct"`
}

// String produces the "<eco>:<name>@<ver>" form used in user-facing
// output. Stable across calls — safe to use as a map key.
func (p PackageRef) String() string {
	return fmt.Sprintf("%s:%s@%s", p.Ecosystem, p.Name, p.Version)
}

// PackageCheck bundles every CheckResult for one PackageRef plus the
// aggregated Decision. Built by Run; consumed by the gate orchestrator
// to decide whether the overall install proceeds.
type PackageCheck struct {
	Package PackageRef    `json:"package"`
	Results []CheckResult `json:"results"`
}

// Decision is the worst Verdict across this package's checks.
// VerdictBlock > VerdictWarn > VerdictApprove > VerdictUnknown.
// Unknown is treated as Block at policy-evaluation time but kept
// distinct here so the failure mode is debuggable ("we couldn't
// reach the registry to check cooldown" is different from "this
// package is known-malicious").
func (pc PackageCheck) Decision() Verdict {
	worst := VerdictApprove
	for _, r := range pc.Results {
		// We don't promote Unknown over Approve here — Unknown
		// gets resolved against policy in Decide(). Within Decision
		// itself, Block > Warn > Approve.
		switch r.Verdict {
		case VerdictBlock:
			worst = VerdictBlock
		case VerdictWarn:
			if worst != VerdictBlock {
				worst = VerdictWarn
			}
		case VerdictUnknown:
			// Surface Unknown only when nothing else fired so the
			// policy layer can decide.
			if worst == VerdictApprove {
				worst = VerdictUnknown
			}
		}
	}
	return worst
}

// Blocked returns the subset of results whose Verdict == Block.
// Used by the CLI to render the rejection summary.
func (pc PackageCheck) Blocked() []CheckResult {
	var out []CheckResult
	for _, r := range pc.Results {
		if r.Verdict == VerdictBlock {
			out = append(out, r)
		}
	}
	return out
}

// Warnings returns the subset of results whose Verdict == Warn.
func (pc PackageCheck) Warnings() []CheckResult {
	var out []CheckResult
	for _, r := range pc.Results {
		if r.Verdict == VerdictWarn {
			out = append(out, r)
		}
	}
	return out
}

// Checker is implemented by each gate-time check (cooldown, OSV,
// publisher-change, static-pattern, etc.). Check is expected to
// respect ctx for cancellation; long-running checks (e.g. tarball
// download) MUST honor it so the gate has a hard upper bound.
//
// Checkers should be safe to call concurrently — the orchestrator
// fans out across packages and may parallelize across checks too.
type Checker interface {
	// Name returns a stable identifier for this checker
	// ("cooldown", "osv-malicious", "static-pattern"). Used in
	// CheckResult.Checker so reasons are attributable.
	Name() string

	// Check returns the verdict for one package. Implementations
	// should populate CheckResult.Checker with their Name() value.
	// On internal errors (network, parse), return
	// Verdict=Unknown with a clear Reason — never panic, never
	// return Approve on error.
	Check(ctx context.Context, ref PackageRef) CheckResult
}

// Policy controls how the gate aggregates per-checker Verdicts into
// an overall accept/reject. Default is "block on Block, allow on
// Warn, fail-closed on Unknown" — the prevention-tool stance.
type Policy struct {
	// AllowOnWarn — let installs through when no checker said
	// Block but some said Warn. Default false (strict). Users can
	// flip this when they want gate-as-advice rather than
	// gate-as-enforcement.
	AllowOnWarn bool

	// AllowOnUnknown — let installs through when checks couldn't
	// complete (offline, registry down). Default false
	// (fail-closed). Set to true with --allow-offline for
	// air-gapped environments where the gate is best-effort.
	AllowOnUnknown bool
}

// Strict is the default Policy: reject Block AND Warn AND Unknown.
// Most cautious posture; suitable for CI gates and production
// developer machines.
func Strict() Policy { return Policy{} }

// Lenient allows Warn-level findings through (still blocks Block,
// still fail-closed on Unknown). Suitable for adoption phases when
// the team is calibrating signal-to-noise.
func Lenient() Policy { return Policy{AllowOnWarn: true} }

// Decide returns true if the package's overall Decision is
// acceptable under p. Returns the controlling Verdict for the
// caller to surface to the user.
func (p Policy) Decide(pc PackageCheck) (allow bool, verdict Verdict) {
	d := pc.Decision()
	switch d {
	case VerdictApprove:
		return true, d
	case VerdictWarn:
		return p.AllowOnWarn, d
	case VerdictUnknown:
		return p.AllowOnUnknown, d
	case VerdictBlock:
		return false, d
	}
	return false, d
}

// Run executes every Checker against every PackageRef, returning the
// per-package aggregated results. Order in the returned slice matches
// the input order (so the caller can render a stable "tree" view).
// Checkers run sequentially per-package; parallelism across packages
// is the caller's choice — we don't fan out here because some
// checkers (cooldown, OSV) share an HTTP-cache and concurrent
// access patterns differ by checker.
func Run(ctx context.Context, checkers []Checker, packages []PackageRef) []PackageCheck {
	out := make([]PackageCheck, 0, len(packages))
	for _, ref := range packages {
		pc := PackageCheck{Package: ref}
		for _, c := range checkers {
			if ctx.Err() != nil {
				pc.Results = append(pc.Results, CheckResult{
					Checker: c.Name(),
					Verdict: VerdictUnknown,
					Reason:  "context cancelled before check could run",
				})
				continue
			}
			pc.Results = append(pc.Results, c.Check(ctx, ref))
		}
		out = append(out, pc)
	}
	return out
}

// Summarize collapses per-package results into a compact
// "N approved, M blocked, P warned" string for stderr banners.
func Summarize(checks []PackageCheck) string {
	var approve, warn, block, unknown int
	for _, pc := range checks {
		switch pc.Decision() {
		case VerdictApprove:
			approve++
		case VerdictWarn:
			warn++
		case VerdictBlock:
			block++
		case VerdictUnknown:
			unknown++
		}
	}
	parts := []string{fmt.Sprintf("approve=%d", approve)}
	if warn > 0 {
		parts = append(parts, fmt.Sprintf("warn=%d", warn))
	}
	if block > 0 {
		parts = append(parts, fmt.Sprintf("block=%d", block))
	}
	if unknown > 0 {
		parts = append(parts, fmt.Sprintf("unknown=%d", unknown))
	}
	return strings.Join(parts, " ")
}

// SortByVerdict reorders a PackageCheck slice so the worst-verdict
// entries come first — the order the user wants when scanning the
// terminal for "what's blocked." Stable within a verdict group; ties
// broken by Package.String().
func SortByVerdict(checks []PackageCheck) {
	sort.SliceStable(checks, func(i, j int) bool {
		di, dj := checks[i].Decision(), checks[j].Decision()
		if di != dj {
			// Higher verdict numbers come first.
			return int(di) > int(dj)
		}
		return checks[i].Package.String() < checks[j].Package.String()
	})
}
