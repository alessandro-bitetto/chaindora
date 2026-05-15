package osvioc

import (
	"fmt"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// PlanFix returns a FixPlan for an OSV-IOC finding. For --deep findings
// (SourcePath identifies the global package manager) the plan carries an
// executable upgrade command at FixSafe category — except apt, which needs
// sudo and is marked FixUnsafe with manual instructions. For project-lockfile
// findings the plan is FixManual: chaindora prints the references and lets
// the human decide on the version bump.
func PlanFix(f findings.Finding) (*findings.FixPlan, bool) {
	if f.Detector != "osv-ioc" {
		return nil, false
	}
	plan := &findings.FixPlan{
		FindingFingerprint: findings.Fingerprint(f),
		Detector:           f.Detector,
		Severity:           f.Severity,
		VulnID:             f.VulnID,
	}
	switch f.SourcePath {
	case "npm:global":
		plan.Description = fmt.Sprintf("Upgrade global npm package %s past %s to address %s", f.Name, f.Version, f.VulnID)
		plan.Category = findings.FixSafe
		plan.Command = fmt.Sprintf("npm install -g %s@latest", shellQuoteArg(f.Name))
		return plan, true
	case "pip:global", "pip3:global":
		plan.Description = fmt.Sprintf("Upgrade pip-installed %s past %s (user install) to address %s", f.Name, f.Version, f.VulnID)
		plan.Category = findings.FixSafe
		plan.Command = fmt.Sprintf("python3 -m pip install --upgrade --user %s", shellQuoteArg(f.Name))
		return plan, true
	case "brew:global":
		plan.Description = fmt.Sprintf("Upgrade Homebrew formula %s past %s to address %s", f.Name, f.Version, f.VulnID)
		plan.Category = findings.FixSafe
		plan.Command = fmt.Sprintf("brew upgrade %s", shellQuoteArg(f.Name))
		return plan, true
	case "dpkg:global":
		plan.Description = fmt.Sprintf("Upgrade apt package %s past %s to address %s", f.Name, f.Version, f.VulnID)
		plan.Category = findings.FixUnsafe // needs sudo; never auto-executed
		plan.ManualSteps = []string{
			fmt.Sprintf("sudo apt-get update && sudo apt-get install --only-upgrade %s", f.Name),
			"Verify the upgrade introduced no unintended package removals before rebooting any services.",
		}
		return plan, true
	}

	// Project-lockfile finding: SourcePath is a file path. v0.3 prints
	// manual guidance; programmatic lockfile editing lands in v0.3.1.
	plan.Description = fmt.Sprintf("Bump %s above %s in %s (%s)", f.Name, f.Version, f.SourcePath, f.VulnID)
	plan.Category = findings.FixManual
	steps := []string{
		fmt.Sprintf("Edit %s to require %s > %s (consult the advisory for the minimum fixed version)", f.SourcePath, f.Name, f.Version),
	}
	if len(f.References) > 0 {
		steps = append(steps, fmt.Sprintf("Advisory: %s", f.References[0]))
	}
	plan.ManualSteps = steps
	return plan, true
}

// shellQuoteArg wraps a package name in single quotes if it contains anything
// other than the conservative set of [A-Za-z0-9._@/+-]. Most npm/pip/brew
// names don't need it but scoped npm names contain @ and / which sh handles
// fine as long as no shell metacharacters slip in.
func shellQuoteArg(s string) string {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '@', r == '/', r == '+', r == '-':
			continue
		default:
			// Quote and escape any embedded single quotes.
			esc := ""
			for _, c := range s {
				if c == '\'' {
					esc += `'\''`
				} else {
					esc += string(c)
				}
			}
			return "'" + esc + "'"
		}
	}
	return s
}
