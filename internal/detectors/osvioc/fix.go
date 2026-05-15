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
	// Global packages — npm -g / pip --user / brew use their own
	// version-selection logic (npm's @latest within the global slot,
	// pip's pip install --upgrade picks the latest compatible) so they
	// don't need the in-major pin treatment lockfile fixes need.
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

	// Project-lockfile fixes: if OSV told us the minimum-fixed version
	// within the current major, pin to that with `^` to allow patch /
	// minor updates inside the same major. This avoids the v0.7.1 bug
	// where `npm install pkg@latest` jumped majors and broke peer deps.
	//
	// FixUpgradeTo == "" means no in-major fix exists — the only way
	// out is a major upgrade. We mark FixManual so the user has to
	// consent explicitly; auto-applying a major bump is the exact
	// foot-gun that produced the 15+ ERESOLVE cascades.
	if f.FixUpgradeTo == "" {
		plan.Description = fmt.Sprintf("%s in %s requires a MAJOR upgrade to address %s (no in-major fix available)", f.Name, f.SourcePath, f.VulnID)
		plan.Category = findings.FixManual
		plan.ManualSteps = []string{
			fmt.Sprintf("No fix exists within the current major version of %s. The only available fix requires a major version bump, which may include breaking changes.", f.Name),
			fmt.Sprintf("Review the advisory, plan the migration, and update %s manually.", f.SourcePath),
		}
		if len(f.References) > 0 {
			plan.ManualSteps = append(plan.ManualSteps, fmt.Sprintf("Advisory: %s", f.References[0]))
		}
		return plan, true
	}

	// Project-lockfile finding: SourcePath is a file path. Map the lockfile
	// to its ecosystem's idiomatic upgrade command. FixSemiSafe — lockfile
	// changes can have surprising transitive effects, so default UX prompts.
	projectDir := filepath.Dir(f.SourcePath)
	lockfile := filepath.Base(f.SourcePath)
	if cmd, manual := projectLockfileFix(lockfile, projectDir, f.Name, f.FixUpgradeTo); cmd != "" {
		plan.Description = fmt.Sprintf("Upgrade %s past %s in %s (%s)", f.Name, f.Version, f.SourcePath, f.VulnID)
		plan.Category = findings.FixSemiSafe
		plan.Command = cmd
		// v0.8.1 package-level dedup keys. The runner collapses
		// plans with the same (ProjectDir, PackageName) into one
		// command pinned to the max RequiredVersion.
		plan.ProjectDir = projectDir
		plan.PackageName = f.Name
		plan.RequiredVersion = f.FixUpgradeTo
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
//
// fixVersion (v0.7.2) is the minimum fixed version within the current
// major, as derived by osv.MinFixedInMajor. Non-empty: pin to
// `pkg@^X.Y.Z` so npm / yarn / pnpm respect peer-dep ranges. Empty: the
// caller has already routed to a FixManual plan (no in-major fix), so
// this function isn't reached.
func projectLockfileFix(lockfile, projectDir, pkgName, fixVersion string) (string, []string) {
	dir := shellQuotePath(projectDir)
	pkg := shellQuoteArg(pkgName)
	// Build the version selector. Caret (`^`) means "any version
	// compatible with X.Y.Z within the same major" per the npm/SemVer
	// rules — exactly what we want to stay inside the current major
	// while picking up the CVE fix.
	verSel := "^" + shellQuoteArg(fixVersion)
	switch lockfile {
	case "package-lock.json":
		return fmt.Sprintf("cd %s && npm install %s@%s", dir, pkg, verSel), nil
	case "yarn.lock":
		return fmt.Sprintf("cd %s && yarn upgrade %s@%s", dir, pkg, verSel), nil
	case "pnpm-lock.yaml":
		return fmt.Sprintf("cd %s && pnpm update %s@%s", dir, pkg, verSel), nil
	case "poetry.lock":
		// Poetry uses `pkg@^X` syntax too.
		return fmt.Sprintf("cd %s && poetry update %s", dir, pkg), nil
	case "uv.lock":
		return fmt.Sprintf("cd %s && uv lock --upgrade-package %s", dir, pkg), nil
	case "Pipfile.lock":
		return fmt.Sprintf("cd %s && pipenv update %s", dir, pkg), nil
	case "requirements.txt":
		// Can't safely line-edit requirements.txt: the existing pin might
		// be exact, a range, an extras clause, or part of a hash spec.
		return "", []string{
			fmt.Sprintf("Edit %s/%s and update the %s pin to ^%s (or any non-vulnerable version)", projectDir, lockfile, pkgName, fixVersion),
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
