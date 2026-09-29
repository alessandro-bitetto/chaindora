package incident

import (
	"fmt"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// PlanFix returns a FixPlan for an incident-pack finding. File-artifact
// matches get `rm` commands at FixSafe; package matches with a known
// SafeVersion get an upgrade command (FixSemiSafe); otherwise package
// matches get an uninstall (FixSemiSafe); ecosystems we can't auto-handle
// (Homebrew/Debian without a clear upgrade verb, browser extensions, CI
// orb references) get manual instructions. Any PostCompromise steps the
// incident declared are surfaced as ManualSteps so credential-rotation
// instructions land in front of the user even when the fix command itself
// is fully automated.
func PlanFix(f findings.Finding) (*findings.FixPlan, bool) {
	if f.Detector != "incident-pack" {
		return nil, false
	}
	plan := &findings.FixPlan{
		FindingFingerprint: findings.Fingerprint(f),
		Detector:           f.Detector,
		Severity:           f.Severity,
		VulnID:             f.VulnID,
	}
	// File-artifact match (no PURL): the matched filename is itself the
	// indicator. For incident-pack entries that gated on `content_substr`
	// the human has high confidence; for filename-only matches the
	// confidence is lower but still actionable.
	if f.PURL == "" && f.SourcePath != "" {
		plan.Description = fmt.Sprintf("Delete incident artifact: %s (%s)", f.SourcePath, f.VulnID)
		plan.Category = findings.FixSafe
		plan.Command = fmt.Sprintf("rm -f -- %s", shellQuote(f.SourcePath))
		plan.ManualSteps = append(plan.ManualSteps, f.PostCompromise...)
		plan.ManualSteps = append(plan.ManualSteps,
			"If this artifact was deployed by a worm with credential-stealing capability, also rotate any tokens accessible from this host.",
		)
		return plan, true
	}

	// Package match. Prefer an upgrade-to-clean-version command when the
	// incident YAML declared a safe_version; otherwise fall back to
	// uninstall.
	switch f.Ecosystem {
	case inventory.EcosystemNPM:
		if f.FixUpgradeTo != "" {
			plan.Description = fmt.Sprintf("Upgrade npm package %s from %s to known-clean %s (%s)", f.Name, f.Version, f.FixUpgradeTo, f.VulnID)
			plan.Category = findings.FixSemiSafe
			plan.Command = fmt.Sprintf("npm install %s@%s", shellQuoteName(f.Name), shellQuoteName(f.FixUpgradeTo))
		} else {
			plan.Description = fmt.Sprintf("Uninstall compromised npm package %s@%s (%s)", f.Name, f.Version, f.VulnID)
			plan.Category = findings.FixSemiSafe
			plan.Command = fmt.Sprintf("npm uninstall %s", shellQuoteName(f.Name))
		}
	case inventory.EcosystemPyPI:
		if f.FixUpgradeTo != "" {
			plan.Description = fmt.Sprintf("Upgrade PyPI package %s from %s to known-clean %s (%s)", f.Name, f.Version, f.FixUpgradeTo, f.VulnID)
			plan.Category = findings.FixSemiSafe
			plan.Command = fmt.Sprintf("python3 -m pip install --upgrade %s==%s", shellQuoteName(f.Name), shellQuoteName(f.FixUpgradeTo))
		} else {
			plan.Description = fmt.Sprintf("Uninstall compromised PyPI package %s@%s (%s)", f.Name, f.Version, f.VulnID)
			plan.Category = findings.FixSemiSafe
			plan.Command = fmt.Sprintf("python3 -m pip uninstall -y %s", shellQuoteName(f.Name))
		}
	case inventory.EcosystemHomebrew:
		plan.Description = fmt.Sprintf("Upgrade Homebrew formula %s past compromised %s (%s)", f.Name, f.Version, f.VulnID)
		plan.Category = findings.FixSemiSafe
		plan.Command = fmt.Sprintf("brew upgrade %s", shellQuoteName(f.Name))
		if f.FixUpgradeTo != "" {
			plan.ManualSteps = append(plan.ManualSteps,
				fmt.Sprintf("Verify the post-upgrade version is at least %s — `brew info %s`.", f.FixUpgradeTo, f.Name),
			)
		}
	default:
		plan.Description = fmt.Sprintf("Remove compromised %s package %s@%s (%s)", f.Ecosystem, f.Name, f.Version, f.VulnID)
		plan.Category = findings.FixManual
		if f.FixUpgradeTo != "" {
			plan.ManualSteps = append(plan.ManualSteps,
				fmt.Sprintf("Upgrade %s from %s to known-clean %s via your %s package manager.", f.Name, f.Version, f.FixUpgradeTo, f.Ecosystem),
			)
		} else {
			plan.ManualSteps = append(plan.ManualSteps,
				fmt.Sprintf("Uninstall %s@%s via your %s package manager.", f.Name, f.Version, f.Ecosystem),
			)
		}
	}
	plan.ManualSteps = append(plan.ManualSteps, f.PostCompromise...)
	plan.ManualSteps = append(plan.ManualSteps,
		"Audit any credentials that may have been exfiltrated during the time this package was installed.",
		"Verify your dependency tree doesn't pull a different vulnerable version transitively.",
	)
	return plan, true
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t'\"\\$`&|;<>()*?[]{}~#!\n") && !strings.HasPrefix(s, "-") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellQuoteName is a narrower quoter for package names — same conservative
// alphabet as the OSV-IOC fixer, but kept local to avoid cross-package
// imports for one helper.
func shellQuoteName(s string) string {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '@', r == '/', r == '+', r == '-':
			continue
		default:
			return shellQuote(s)
		}
	}
	return s
}
