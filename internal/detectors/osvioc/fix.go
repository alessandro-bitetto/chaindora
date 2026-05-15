package osvioc

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// PlanFix returns a FixPlan for an OSV-IOC finding. SourcePath identifies the
// fix target: "<pkgmgr>:global" → safe upgrade command for globally-installed
// packages; a real file path → project-lockfile remediation (FixSemiSafe
// upgrade command for npm/yarn/pnpm/poetry/uv/pipenv, FixManual instructions
// for requirements.txt).
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
		plan.Category = findings.FixUnsafe
		plan.ManualSteps = []string{
			fmt.Sprintf("sudo apt-get update && sudo apt-get install --only-upgrade %s", f.Name),
			"Verify the upgrade introduced no unintended package removals before rebooting any services.",
		}
		return plan, true
	}

	// Project-lockfile finding: SourcePath is a file path. Map the lockfile
	// to its ecosystem's idiomatic upgrade command. FixSemiSafe — lockfile
	// changes can have surprising transitive effects, so default UX prompts.
	projectDir := filepath.Dir(f.SourcePath)
	lockfile := filepath.Base(f.SourcePath)
	if cmd, manual := projectLockfileFix(lockfile, projectDir, f.Name); cmd != "" {
		plan.Description = fmt.Sprintf("Upgrade %s past %s in %s (%s)", f.Name, f.Version, f.SourcePath, f.VulnID)
		plan.Category = findings.FixSemiSafe
		plan.Command = cmd
		steps := []string{"Review the resulting lockfile diff before committing."}
		if len(f.References) > 0 {
			steps = append(steps, fmt.Sprintf("Advisory: %s", f.References[0]))
		}
		plan.ManualSteps = steps
		return plan, true
	} else if len(manual) > 0 {
		plan.Description = fmt.Sprintf("Bump %s above %s in %s (%s)", f.Name, f.Version, f.SourcePath, f.VulnID)
		plan.Category = findings.FixManual
		plan.ManualSteps = manual
		if len(f.References) > 0 {
			plan.ManualSteps = append(plan.ManualSteps, fmt.Sprintf("Advisory: %s", f.References[0]))
		}
		return plan, true
	}

	// Unknown lockfile or non-file SourcePath — fall back to generic manual.
	plan.Description = fmt.Sprintf("Bump %s above %s in %s (%s)", f.Name, f.Version, f.SourcePath, f.VulnID)
	plan.Category = findings.FixManual
	plan.ManualSteps = []string{
		fmt.Sprintf("Edit %s to require %s > %s (consult the advisory for the minimum fixed version)", f.SourcePath, f.Name, f.Version),
	}
	if len(f.References) > 0 {
		plan.ManualSteps = append(plan.ManualSteps, fmt.Sprintf("Advisory: %s", f.References[0]))
	}
	return plan, true
}

// projectLockfileFix returns (command, manualSteps). Command non-empty →
// caller emits FixSemiSafe with the command. Command empty but manualSteps
// non-empty → caller emits FixManual with those steps. Both empty → caller
// falls back to its own generic manual plan.
func projectLockfileFix(lockfile, projectDir, pkgName string) (string, []string) {
	dir := shellQuotePath(projectDir)
	pkg := shellQuoteArg(pkgName)
	switch lockfile {
	case "package-lock.json":
		return fmt.Sprintf("cd %s && npm install %s@latest", dir, pkg), nil
	case "yarn.lock":
		return fmt.Sprintf("cd %s && yarn upgrade %s --latest", dir, pkg), nil
	case "pnpm-lock.yaml":
		return fmt.Sprintf("cd %s && pnpm update --latest %s", dir, pkg), nil
	case "poetry.lock":
		return fmt.Sprintf("cd %s && poetry update %s", dir, pkg), nil
	case "uv.lock":
		return fmt.Sprintf("cd %s && uv lock --upgrade-package %s", dir, pkg), nil
	case "Pipfile.lock":
		return fmt.Sprintf("cd %s && pipenv update %s", dir, pkg), nil
	case "requirements.txt":
		// Can't safely line-edit requirements.txt: the existing pin might
		// be exact, a range, an extras clause, or part of a hash spec.
		return "", []string{
			fmt.Sprintf("Edit %s/%s and update the %s pin to a non-vulnerable version", projectDir, lockfile, pkgName),
			fmt.Sprintf("Then: cd %s && python3 -m pip install -r %s --upgrade", projectDir, lockfile),
		}
	}
	return "", nil
}

// shellQuoteArg wraps a package name in single quotes if it contains anything
// outside the conservative set of [A-Za-z0-9._@/+-].
func shellQuoteArg(s string) string {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '@', r == '/', r == '+', r == '-':
			continue
		default:
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}

// shellQuotePath quotes a filesystem path safely for `sh -c`.
func shellQuotePath(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '/', r == '-':
			continue
		default:
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}
