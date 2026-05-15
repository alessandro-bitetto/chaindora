package gate

import (
	"context"
	"fmt"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

// Cooldown is the gate's most important single check: it refuses to
// install any package version published less than Threshold ago.
//
// Empirically, malicious npm packages get yanked by the npm security
// team within hours-to-1-day of publication; major worms
// (shai-hulud, qix, ctx, eslint-config-prettier, ua-parser-js) are
// all reported and removed inside a 72-hour window. A blanket
// "don't install brand-new versions" rule blocks the entire
// 0-day window without you needing to know about the specific attack.
//
// The cost: legitimate fresh patches (security CVE fixes!) also get
// blocked for the cooldown period. That's the tradeoff users
// explicitly opt into. The per-project allowlist (chaindora.yml)
// is the escape hatch: name a specific (pkg, version) and the
// cooldown is bypassed for it.
//
// Default threshold is 72 hours — generous enough to catch
// every recent npm supply-chain attack we know of, short enough
// that "I want to use today's hotfix" is only a 3-day wait.
type Cooldown struct {
	Threshold time.Duration
	NPM       npmCooldownProbe
	PyPI      pypiCooldownProbe
}

// npmCooldownProbe is the subset of registries.NPM the cooldown
// checker needs. Defined as an interface so tests can inject a
// fake without importing the real HTTP probe.
type npmCooldownProbe interface {
	PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error)
}

// pypiCooldownProbe mirrors npmCooldownProbe for PyPI. Same
// shape so cooldown can dispatch on ecosystem without
// reimplementing per-probe.
type pypiCooldownProbe interface {
	PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error)
}

// NewCooldown returns a Cooldown configured with the supplied
// threshold and the default public-registry probes for both
// npm and PyPI.
func NewCooldown(threshold time.Duration) *Cooldown {
	if threshold <= 0 {
		threshold = 72 * time.Hour
	}
	return &Cooldown{
		Threshold: threshold,
		NPM:       registries.NewNPM(),
		PyPI:      registries.NewPyPI(),
	}
}

func (c *Cooldown) Name() string { return "cooldown" }

func (c *Cooldown) Check(ctx context.Context, ref PackageRef) CheckResult {
	result := CheckResult{Checker: c.Name()}
	if ref.Version == "" {
		result.Verdict = VerdictUnknown
		result.Reason = "no resolved version to check"
		return result
	}
	var publishedAt time.Time
	var err error
	switch ref.Ecosystem {
	case "npm":
		publishedAt, err = c.NPM.PublishedAtVersion(ctx, ref.Name, ref.Version)
	case "pypi", "pip":
		if c.PyPI == nil {
			result.Verdict = VerdictUnknown
			result.Reason = "no PyPI probe configured"
			return result
		}
		publishedAt, err = c.PyPI.PublishedAtVersion(ctx, ref.Name, ref.Version)
	default:
		// Other ecosystems aren't wired yet (RubyGems / crates /
		// Maven in v0.11). Skipping is safer than guessing —
		// return Unknown so the fail-closed policy still applies
		// unless the user explicitly --allow-offline.
		result.Verdict = VerdictUnknown
		result.Reason = fmt.Sprintf("cooldown not implemented for ecosystem %q", ref.Ecosystem)
		return result
	}
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

// humanDuration renders a Duration in the shape users expect from a
// cooldown message: "14m", "3h", "5d 2h", "29d" — never the
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
