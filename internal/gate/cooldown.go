package gate

import (
	"context"
	"fmt"
	"time"
)

// Cooldown is the gate's most important single check: it refuses
// to install any package version published less than Threshold
// ago. Empirically, malicious packages get yanked by the registry
// security team within hours-to-1-day of publication; major
// supply-chain worms (shai-hulud, qix, ctx, eslint-config-prettier,
// ua-parser-js) are all reported and removed inside a 72-hour
// window. A blanket "don't install brand-new versions" rule
// blocks the entire 0-day window without you needing to know
// about the specific attack.
//
// Per-project allowlist (chaindora.yml) is the escape hatch: name
// a specific (pkg, version) and the cooldown is bypassed for it.
//
// Default threshold is 72 hours.
type Cooldown struct {
	Threshold time.Duration
	Probes    *Probes
}

// NewCooldown returns a Cooldown configured with the supplied
// threshold. Callers should populate Probes before adding to the
// checker stack — typically via the cli package's gate-wiring
// helpers.
func NewCooldown(threshold time.Duration) *Cooldown {
	if threshold <= 0 {
		threshold = 72 * time.Hour
	}
	return &Cooldown{
		Threshold: threshold,
		Probes:    NewProbes(),
	}
}

func (c *Cooldown) Name() string { return "cooldown" }

func (c *Cooldown) Check(ctx context.Context, ref PackageRef) CheckResult {
	result := CheckResult{Checker: c.Name()}
	if ref.Ecosystem == "git" {
		// Git-URL packages have no registry publish-date concept.
		// The GitURLCheck handles them via ref-pinning + host-
		// trust. We pass through cleanly here so the fail-closed
		// Unknown policy doesn't block legitimate pinned-SHA
		// git deps.
		result.Verdict = VerdictApprove
		result.Reason = "cooldown: git-URL deps evaluated by git-url checker, not registry cooldown"
		return result
	}
	if ref.Version == "" {
		result.Verdict = VerdictUnknown
		result.Reason = "no resolved version to check"
		return result
	}
	probe, ok := c.Probes.versionProbeFor(ref.Ecosystem)
	if !ok {
		result.Verdict = VerdictUnknown
		result.Reason = fmt.Sprintf("cooldown: no registry probe for ecosystem %q", ref.Ecosystem)
		return result
	}
	publishedAt, err := probe.PublishedAtVersion(ctx, ref.Name, ref.Version)
	if err != nil {
		result.Verdict = VerdictUnknown
		result.Reason = fmt.Sprintf("registry lookup failed: %v", err)
		return result
	}
	if publishedAt.IsZero() {
		result.Verdict = VerdictUnknown
		result.Reason = "registry returned no publish date for this version"
		return result
	}
	age := time.Since(publishedAt)
	if age < c.Threshold {
		result.Verdict = VerdictBlock
		result.Reason = fmt.Sprintf("published %s ago, below cooldown threshold %s",
			humanDuration(age), humanDuration(c.Threshold))
		result.Detail = fmt.Sprintf("publish timestamp: %s", publishedAt.UTC().Format(time.RFC3339))
		return result
	}
	result.Verdict = VerdictApprove
	result.Reason = fmt.Sprintf("published %s ago (≥ cooldown %s)", humanDuration(age), humanDuration(c.Threshold))
	return result
}

// humanDuration renders a Duration in the shape users expect from
// a cooldown message: "14m", "3h", "5d 2h", "29d" — never the
// stock-Go "359h44m" form.
func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) - h*60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh %dm", h, m)
	}
	days := int(d.Hours() / 24)
	h := int(d.Hours()) - days*24
	if h == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd %dh", days, h)
}
