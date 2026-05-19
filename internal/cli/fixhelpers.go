package cli

import (
	"fmt"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/detectors/incident"
	"github.com/alessandro-bitetto/chaindora/internal/detectors/osvioc"
	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// buildAllFixPlans dispatches each finding to its detector's PlanFix and
// falls back to manualPlanFromFinding for detectors that don't yet expose a
// programmatic fix (heuristic, hostforensics). Result is one deduped FixPlan
// per (project, package) for lockfile upgrades; one per command otherwise.
//
// Dedup happens here, not at apply-time, so that saved plans (`--save-plan`)
// already reflect what will execute — `chdora plans show` and the saved
// JSON match the eventual run.
func buildAllFixPlans(fs []findings.Finding) []findings.FixPlan {
	plans := make([]findings.FixPlan, 0, len(fs))
	for _, f := range fs {
		// Predictive findings (maintainer-trust dormancy, publisher-
		// change, provenance regression, version-diff) are advisory
		// behavioral signals — there's no command to run, and the
		// renderer already condenses them via writePredictiveSection.
		// Wrapping each one in a "Manual review required" FixPlan
		// produces thousands of entries that drown the actually-
		// fixable items in `chdora fix`. Drop them here below
		// Critical. Critical predictive findings (republish-guard:
		// same name@version with different integrity — hard tamper
		// signal) keep their slot and get a real instruction below.
		if strings.HasPrefix(f.Detector, "predictive:") && f.Severity != findings.SeverityCritical {
			continue
		}
		var plan *findings.FixPlan
		var ok bool
		switch f.Detector {
		case "osv-ioc":
			plan, ok = osvioc.PlanFix(f)
		case "incident-pack":
			plan, ok = incident.PlanFix(f)
		default:
			plan = manualPlanFromFinding(f)
			ok = true
		}
		if ok && plan != nil {
			plans = append(plans, *plan)
		}
	}
	return findings.DedupePlans(plans)
}

// manualPlanFromFinding emits a manual-instructions FixPlan for findings the
// scanner can't safely automate — credentials need rotation, shell rcs need
// human triage, ssh keys can't be told apart by chdora. The plan still
// surfaces clear remediation steps so the user has somewhere to start.
func manualPlanFromFinding(f findings.Finding) *findings.FixPlan {
	var steps []string
	switch {
	case strings.HasPrefix(f.Detector, "hostforensics:tokens"):
		steps = []string{
			fmt.Sprintf("Rotate the credential stored at %s via the provider's UI / API.", f.SourcePath),
			"After rotation, restart any process or service that read the old credential.",
		}
	case strings.HasPrefix(f.Detector, "hostforensics:shellrc"),
		strings.HasPrefix(f.Detector, "hostforensics:powershell"):
		steps = []string{
			fmt.Sprintf("Open %s and inspect the flagged line(s) for legitimate use.", f.SourcePath),
			"If suspicious, remove the line(s) and rotate any credentials accessible from this shell.",
		}
	case strings.HasPrefix(f.Detector, "hostforensics:ssh"):
		steps = []string{
			fmt.Sprintf("Audit %s — confirm every key is one you authorized.", f.SourcePath),
			"If a key is unfamiliar, remove it AND rotate the account it grants access to.",
		}
	case strings.HasPrefix(f.Detector, "hostforensics:persistence"):
		steps = []string{
			fmt.Sprintf("Review %s.", f.SourcePath),
			"If unauthorized: remove via the relevant tool (crontab -e / systemctl --user disable / move plist out of LaunchAgents / schtasks /Delete) and audit when it was created.",
		}
	case strings.HasPrefix(f.Detector, "heuristic:"):
		steps = []string{
			"This is a behavioral signal, not a confirmed compromise — manual triage required.",
			fmt.Sprintf("Source: %s", f.SourcePath),
		}
	case strings.HasPrefix(f.Detector, "integrity:lockfile-vs-disk"),
		f.Detector == "integrity:lockfile-mirror-drift":
		// Installed bytes diverge from the lockfile pin. Most common
		// cause is a stale `npm install <pkg>` against an existing
		// lockfile; the malicious case is a tampered node_modules
		// directory. Re-running from the lockfile restores the
		// pinned state regardless of cause, and surfaces tampering
		// if the integrity hash still fails after re-install.
		steps = []string{
			fmt.Sprintf("Inspect %s — confirm the package directory hasn't been replaced or symlinked.", f.SourcePath),
			"From the project root: delete node_modules/ and re-run the lockfile-strict install (`npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable`).",
			"If the install fails on integrity afterwards, the upstream tarball or the lockfile entry was tampered with — investigate before re-pinning.",
		}
	case f.Detector == "hostforensics:trustdrift":
		steps = []string{
			fmt.Sprintf("Diff %s against your last-known-good baseline.", f.SourcePath),
			"If the change is unexpected, restore the file from version control / a clean machine and re-baseline (`chdora forensics --trust-drift-update-baseline`).",
		}
	case f.Detector == "predictive:republish-guard":
		steps = []string{
			fmt.Sprintf("HARD TAMPER SIGNAL: same %s@%s observed with a different integrity hash than the cached entry.", f.Name, f.Version),
			"Do not reinstall until verified: check the registry's published-versions list and the maintainer's release notes for a legitimate republish.",
			"If unverified, clear the gate cache (`chdora gate cache clear`) only after confirming the new integrity is the intended one.",
		}
	default:
		steps = []string{
			fmt.Sprintf("Manual review required: %s — %s", f.VulnID, f.Summary),
		}
	}
	return &findings.FixPlan{
		FindingFingerprint: findings.Fingerprint(f),
		Detector:           f.Detector,
		Severity:           f.Severity,
		VulnID:             f.VulnID,
		Description:        f.Summary,
		Category:           findings.FixManual,
		ManualSteps:        steps,
	}
}
