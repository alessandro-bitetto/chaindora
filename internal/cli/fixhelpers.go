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
// programmatic fix (heuristic, hostforensics). Result is one FixPlan per
// finding, in input order.
func buildAllFixPlans(fs []findings.Finding) []findings.FixPlan {
	plans := make([]findings.FixPlan, 0, len(fs))
	for _, f := range fs {
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
	return plans
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
