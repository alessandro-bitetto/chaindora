package findings

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunFixesPlanOnly(t *testing.T) {
	plans := []FixPlan{
		{Description: "Upgrade A", Category: FixSafe, Command: "echo a", Severity: SeverityHigh, VulnID: "X-1"},
		{Description: "Upgrade B", Category: FixSafe, Command: "echo b", Severity: SeverityMedium, VulnID: "X-2"},
	}
	var out bytes.Buffer
	applied, skipped, err := RunFixes(context.Background(), plans, RunOptions{
		PlanOnly: true,
		Output:   &out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if applied != 0 || skipped != 0 {
		t.Errorf("plan-only mode should not increment applied or skipped (got applied=%d skipped=%d)", applied, skipped)
	}
	if !strings.Contains(out.String(), "Upgrade A") || !strings.Contains(out.String(), "Upgrade B") {
		t.Errorf("plan-only output missing descriptions: %s", out.String())
	}
}

func TestRunFixesAutoYesSafe(t *testing.T) {
	plans := []FixPlan{
		{Description: "safe one", Category: FixSafe, Command: "true", Severity: SeverityHigh, VulnID: "X-1"},
		{Description: "manual one", Category: FixManual, ManualSteps: []string{"do it"}, Severity: SeverityHigh, VulnID: "X-2"},
	}
	var out bytes.Buffer
	applied, skipped, err := RunFixes(context.Background(), plans, RunOptions{
		AutoYes:           true,
		AllowedCategories: []FixCategory{FixSafe},
		Output:            &out,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if applied != 1 {
		t.Errorf("expected 1 applied (the safe one), got %d", applied)
	}
	if skipped != 1 {
		t.Errorf("expected 1 skipped (manual), got %d", skipped)
	}
}

func TestRunFixesPromptApply(t *testing.T) {
	plans := []FixPlan{
		// Different Commands so dedup doesn't collapse them.
		{Description: "Plan 1", Category: FixSafe, Command: "true # plan1", Severity: SeverityHigh, VulnID: "X-1"},
		{Description: "Plan 2", Category: FixSafe, Command: "true # plan2", Severity: SeverityHigh, VulnID: "X-2"},
	}
	stdin := strings.NewReader("a\ns\n")
	var out bytes.Buffer
	applied, skipped, _ := RunFixes(context.Background(), plans, RunOptions{
		Stdin:  stdin,
		Output: &out,
	})
	if applied != 1 {
		t.Errorf("expected 1 applied (responded 'a' to first), got %d", applied)
	}
	if skipped != 1 {
		t.Errorf("expected 1 skipped (responded 's' to second), got %d", skipped)
	}
}

func TestRunFixesPromptQuit(t *testing.T) {
	plans := []FixPlan{
		{Description: "Plan 1", Category: FixSafe, Command: "true # plan1", Severity: SeverityHigh, VulnID: "X-1"},
		{Description: "Plan 2", Category: FixSafe, Command: "true # plan2", Severity: SeverityHigh, VulnID: "X-2"},
	}
	stdin := strings.NewReader("q\n")
	var out bytes.Buffer
	applied, _, _ := RunFixes(context.Background(), plans, RunOptions{
		Stdin:  stdin,
		Output: &out,
	})
	if applied != 0 {
		t.Errorf("quit on first prompt → applied should be 0, got %d", applied)
	}
}

func TestRunFixesDedupesByCommand(t *testing.T) {
	plans := []FixPlan{
		{Description: "fix pip A", Command: "python3 -m pip install --upgrade --user pip", Category: FixSafe, Severity: SeverityLow, VulnID: "X-1"},
		{Description: "fix pip B", Command: "python3 -m pip install --upgrade --user pip", Category: FixSafe, Severity: SeverityHigh, VulnID: "X-2"},
		{Description: "fix pip C", Command: "python3 -m pip install --upgrade --user pip", Category: FixSafe, Severity: SeverityMedium, VulnID: "X-3"},
		{Description: "fix setuptools", Command: "python3 -m pip install --upgrade --user setuptools", Category: FixSafe, Severity: SeverityHigh, VulnID: "Y-1"},
	}
	deduped := dedupePlansByCommand(plans)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 plans after dedup, got %d: %+v", len(deduped), deduped)
	}
	// Highest-severity wins for the kept "pip" entry.
	if deduped[0].Severity != SeverityHigh || deduped[0].VulnID != "X-2" {
		t.Errorf("dedup didn't keep highest severity: %+v", deduped[0])
	}
}

func TestSeverityRank(t *testing.T) {
	cases := []struct {
		a, b Severity
		want bool // a > b ?
	}{
		{SeverityCritical, SeverityHigh, true},
		{SeverityHigh, SeverityMedium, true},
		{SeverityMedium, SeverityLow, true},
		{SeverityLow, SeverityUnknown, true},
		{SeverityHigh, SeverityCritical, false},
	}
	for _, c := range cases {
		got := severityRank(c.a) > severityRank(c.b)
		if got != c.want {
			t.Errorf("%s > %s = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
