package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// TestFixFromFileBuildsPlans is an integration test of the read-file →
// buildAllFixPlans → RunFixes pipeline that backs `chaindora fix --from`.
// We don't invoke the cobra command itself (cobra flag wiring is exercised
// in real `--help` tests); we verify the buildAllFixPlans dispatch + the
// runner's plan-only mode produce the expected output shape.
func TestFixFromFileBuildsPlans(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "findings.json")
	fs := []findings.Finding{
		{
			Detector:   "osv-ioc",
			PURL:       "pkg:npm/lodash@4.17.20",
			Ecosystem:  inventory.EcosystemNPM,
			Name:       "lodash",
			Version:    "4.17.20",
			VulnID:     "GHSA-35jh-r3h4-6jhm",
			Summary:    "Command Injection in lodash",
			Severity:   findings.SeverityHigh,
			SourcePath: "/proj/package-lock.json",
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
