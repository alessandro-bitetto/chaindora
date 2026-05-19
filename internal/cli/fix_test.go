package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// TestFixFromFileBuildsPlans is an integration test of the read-file →
// buildAllFixPlans → RunFixes pipeline that backs `chdora fix --from`.
// We don't invoke the cobra command itself (cobra flag wiring is exercised
// in real `--help` tests); we verify the buildAllFixPlans dispatch + the
// runner's plan-only mode produce the expected output shape.
func TestFixFromFileBuildsPlans(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "findings.json")
	fs := []findings.Finding{
		{
			Detector:     "osv-ioc",
			PURL:         "pkg:npm/lodash@4.17.20",
			Ecosystem:    inventory.EcosystemNPM,
			Name:         "lodash",
			Version:      "4.17.20",
			VulnID:       "GHSA-35jh-r3h4-6jhm",
			Summary:      "Command Injection in lodash",
			Severity:     findings.SeverityHigh,
			SourcePath:   "/proj/package-lock.json",
			FixUpgradeTo: "4.17.21", // v0.7.2: min-fixed-in-major required for FixSemiSafe
		},
		{
			Detector:   "osv-ioc",
			PURL:       "pkg:pypi/pip@21.2.4",
			Ecosystem:  inventory.EcosystemPyPI,
			Name:       "pip",
			Version:    "21.2.4",
			VulnID:     "GHSA-mq26",
			Summary:    "Command Injection in pip",
			Severity:   findings.SeverityMedium,
			SourcePath: "pip:global",
		},
	}
	data, _ := json.MarshalIndent(fs, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// Re-read and exercise the pipeline.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var loaded []findings.Finding
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatal(err)
	}
	plans := buildAllFixPlans(loaded)
	if len(plans) != 2 {
		t.Fatalf("expected 2 plans, got %d: %+v", len(plans), plans)
	}
	// Plan 0 is the package-lock.json → semi-safe npm install command.
	if plans[0].Category != findings.FixSemiSafe {
		t.Errorf("npm project-lockfile plan should be FixSemiSafe, got %q", plans[0].Category)
	}
	if plans[0].Command == "" {
		t.Errorf("npm project-lockfile plan should have an executable Command")
	}
	// Plan 1 is the pip:global → safe upgrade command.
	if plans[1].Category != findings.FixSafe {
		t.Errorf("pip:global plan should be FixSafe, got %q", plans[1].Category)
	}

	// PlanOnly should report without executing.
	applied, skipped, err := findings.RunFixes(context.Background(), plans, findings.RunOptions{
		PlanOnly: true,
		Output:   os.Stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if applied != 0 || skipped != 0 {
		t.Errorf("plan-only should leave counters at zero, got applied=%d skipped=%d", applied, skipped)
	}
}

// TestBuildAllFixPlansDropsNonCriticalPredictive guards the v0.16+ behavior
// where soft-signal predictive findings (publisher-change, maintainer-trust
// dormancy, version-diff) no longer produce stub "Manual review required"
// entries in the fix plan. They're advisory — already condensed by the
// renderer's writePredictiveSection — and were drowning real fixes (one
// audit of a multi-project workspace produced 2500+ such stubs).
// Critical predictive findings (republish-guard) are kept and get a real
// instruction step.
func TestBuildAllFixPlansDropsNonCriticalPredictive(t *testing.T) {
	fs := []findings.Finding{
		// Should be dropped: low-severity advisory predictive.
		{Detector: "predictive:publisher-change", Severity: findings.SeverityLow, Summary: "publisher changed"},
		{Detector: "predictive:maintainer-trust", Severity: findings.SeverityLow, Summary: "dormancy"},
		{Detector: "predictive:version-diff", Severity: findings.SeverityMedium, Summary: "pattern delta"},
		// Should be kept: critical predictive (republish-guard hard tamper signal).
		{
			Detector: "predictive:republish-guard",
			Severity: findings.SeverityCritical,
			Name:     "lodash",
			Version:  "4.17.21",
			Summary:  "integrity mismatch on republish",
			VulnID:   "REPUBLISH-GUARD",
		},
		// Should be kept: integrity drift gets an actionable npm-ci step.
		{
			Detector:   "integrity:lockfile-vs-disk-version",
			Severity:   findings.SeverityCritical,
			Name:       "react",
			Version:    "19.2.4",
			Summary:    "version mismatch",
			VulnID:     "INTEGRITY-DRIFT-VERSION",
			SourcePath: "/proj/package-lock.json",
		},
	}
	plans := buildAllFixPlans(fs)
	if len(plans) != 2 {
		t.Fatalf("expected 2 plans (republish-guard + integrity-drift), got %d: %+v", len(plans), plans)
	}

	var foundRepublish, foundIntegrity bool
	for _, p := range plans {
		switch p.Detector {
		case "predictive:republish-guard":
			foundRepublish = true
			if len(p.ManualSteps) < 2 {
				t.Errorf("republish-guard plan should have multiple manual steps, got %v", p.ManualSteps)
			}
		case "integrity:lockfile-vs-disk-version":
			foundIntegrity = true
			joined := strings.Join(p.ManualSteps, "\n")
			if !strings.Contains(joined, "npm ci") {
				t.Errorf("integrity-drift plan should reference `npm ci` recovery, got steps:\n%s", joined)
			}
		}
	}
	if !foundRepublish {
		t.Errorf("predictive:republish-guard plan was filtered out — only non-critical predictive should drop")
	}
	if !foundIntegrity {
		t.Errorf("integrity:lockfile-vs-disk-version plan missing")
	}
}
