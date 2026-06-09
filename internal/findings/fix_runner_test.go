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
	// CoveredVulnIDs should contain every collapsed VulnID, deduplicated
	// and sorted, so the user can see the full set.
	pipPlan := deduped[0]
	if len(pipPlan.CoveredVulnIDs) != 3 {
		t.Fatalf("expected 3 covered vuln IDs on pip plan, got %d: %+v", len(pipPlan.CoveredVulnIDs), pipPlan.CoveredVulnIDs)
	}
	wantIDs := []string{"X-1", "X-2", "X-3"}
	for i, id := range wantIDs {
		if pipPlan.CoveredVulnIDs[i] != id {
			t.Errorf("CoveredVulnIDs[%d] = %q, want %q (full: %+v)", i, pipPlan.CoveredVulnIDs[i], id, pipPlan.CoveredVulnIDs)
		}
	}
	// Single-finding plan should also have CoveredVulnIDs (length 1).
	suPlan := deduped[1]
	if len(suPlan.CoveredVulnIDs) != 1 || suPlan.CoveredVulnIDs[0] != "Y-1" {
		t.Errorf("single-finding plan should have CoveredVulnIDs=[Y-1], got %+v", suPlan.CoveredVulnIDs)
	}
}

// TestRunFixes_BlastRadiusRecap verifies the pre-apply summary groups
// fixes by directory and flags repos with uncommitted changes, using an
// injected RepoStatus so the test needs no real git tree.
func TestRunFixes_BlastRadiusRecap(t *testing.T) {
	plans := []FixPlan{
		{Description: "fix dirty", Category: FixSafe, Command: "true # a", Severity: SeverityHigh, VulnID: "X-1",
			ProjectDir: "/repo/dirty", PackageName: "a", RequiredVersion: "1.0.0"},
		{Description: "fix clean", Category: FixSafe, Command: "true # b", Severity: SeverityHigh, VulnID: "X-2",
			ProjectDir: "/repo/clean", PackageName: "b", RequiredVersion: "1.0.0"},
	}
	stub := func(dir string) RepoState {
		if dir == "/repo/dirty" {
			return RepoState{IsRepo: true, Dirty: 3}
		}
		return RepoState{IsRepo: true, Dirty: 0}
	}
	var out bytes.Buffer
	applied, _, err := RunFixes(context.Background(), plans, RunOptions{
		AutoYes:           true,
		AllowedCategories: []FixCategory{FixSafe},
		Output:            &out,
		RepoStatus:        stub,
	})
	if err != nil {
		t.Fatal(err)
	}
	if applied != 2 {
		t.Fatalf("expected 2 applied, got %d", applied)
	}
	s := out.String()
	for _, want := range []string{"blast radius", "uncommitted change", "git diff"} {
		if !strings.Contains(s, want) {
			t.Errorf("recap missing %q in:\n%s", want, s)
		}
	}
}

// TestRunFixes_ApplyAllRequiresConfirm covers the safety gate on the
// capital-A "apply all remaining" path: it must show a recap and only go
// unattended on an explicit y/yes.
func TestRunFixes_ApplyAllRequiresConfirm(t *testing.T) {
	mk := func() []FixPlan {
		return []FixPlan{
			{Description: "Plan 1", Category: FixSafe, Command: "true # p1", Severity: SeverityHigh, VulnID: "X-1"},
			{Description: "Plan 2", Category: FixSafe, Command: "true # p2", Severity: SeverityHigh, VulnID: "X-2"},
		}
	}
	// 'A' then 'y' → both apply unattended.
	var out bytes.Buffer
	applied, _, _ := RunFixes(context.Background(), mk(), RunOptions{
		Stdin:  strings.NewReader("A\ny\n"),
		Output: &out,
	})
	if applied != 2 {
		t.Errorf("A then 'y' should apply all (2), got %d", applied)
	}
	if !strings.Contains(out.String(), "apply-all will run") {
		t.Errorf("missing apply-all recap in:\n%s", out.String())
	}
	// 'A' then 'n' → cancelled; fall back to one-at-a-time, then skip.
	var out2 bytes.Buffer
	applied2, _, _ := RunFixes(context.Background(), mk(), RunOptions{
		Stdin:  strings.NewReader("A\nn\ns\n"),
		Output: &out2,
	})
	if applied2 != 0 {
		t.Errorf("A then 'n' should cancel apply-all (0 applied), got %d", applied2)
	}
	if !strings.Contains(out2.String(), "apply-all cancelled") {
		t.Errorf("missing cancel message in:\n%s", out2.String())
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

func TestLooksLikePipInstall(t *testing.T) {
	cases := []struct {
		cmd  string
		want bool
	}{
		{"pip install foo", true},
		{"pip install --upgrade --user foo", true},
		{"python3 -m pip install foo", true},
		{"python -m pip install --upgrade foo", true},
		{"python3.12 -m pip install foo", true},
		{"npm install foo", false},
		{"pip uninstall foo", false},
		{"pip show pip", false},
		{"brew upgrade chdora", false},
		{"", false},
	}
	for _, c := range cases {
		if got := looksLikePipInstall(c.cmd); got != c.want {
			t.Errorf("looksLikePipInstall(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

func TestIsPipNoOp(t *testing.T) {
	// The headline case from the field: pip 26.0.1 is the latest installable
	// on Python 3.9 because pip 26.1+ requires Python 3.10. The command runs
	// cleanly but no "Successfully installed" line appears.
	noOp := `Requirement already satisfied: pip in ./Library/Python/3.9/lib/python/site-packages (26.0.1)
`
	if !isPipNoOp("python3 -m pip install --upgrade --user pip", noOp) {
		t.Error("expected noOp on absent 'Successfully installed' line")
	}

	// Real upgrade — "Requirement already satisfied" appears for the
	// system-site copy first, then "Successfully installed" lands the new
	// version in user-site. Must NOT be flagged.
	upgraded := `Requirement already satisfied: pip in /Library/Developer/CommandLineTools/... (21.2.4)
Collecting pip
  Downloading pip-26.0.1-py3-none-any.whl (1.8 MB)
Installing collected packages: pip
Successfully installed pip-26.0.1
`
	if isPipNoOp("python3 -m pip install --upgrade --user pip", upgraded) {
		t.Error("real upgrade flagged as noOp")
	}

	// Non-pip command: pass through.
	if isPipNoOp("brew upgrade chdora", "") {
		t.Error("non-pip command flagged as noOp")
	}
}
