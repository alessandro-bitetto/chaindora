package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/fixplan"
)

func TestEmitPriorApplyBanner_SkipsForUnappliedPlan(t *testing.T) {
	var buf bytes.Buffer
	emitPriorApplyBanner(&buf, fixplan.Plan{ID: "x"})
	if buf.Len() != 0 {
		t.Errorf("unapplied plan should emit no banner, got %q", buf.String())
	}
}

func TestEmitPriorApplyBanner_PrintsApplyHistory(t *testing.T) {
	applied := time.Date(2026, 5, 15, 20, 48, 23, 0, time.UTC)
	plan := fixplan.Plan{
		ID:        "2026-05-15-a558",
		AppliedAt: &applied,
		AppliedResults: []fixplan.AppliedResult{
			{Status: "applied"},
			{Status: "applied"},
			{Status: "already-satisfied"},
			{Status: "skipped"},
		},
	}
	var buf bytes.Buffer
	emitPriorApplyBanner(&buf, plan)
	out := buf.String()
	if !strings.Contains(out, "previously applied") {
		t.Errorf("banner should call out the prior apply, got %q", out)
	}
	if !strings.Contains(out, "applied=2") {
		t.Errorf("banner should report 2 applied, got %q", out)
	}
	if !strings.Contains(out, "already-satisfied=1") {
		t.Errorf("banner should report 1 already-satisfied, got %q", out)
	}
	if !strings.Contains(out, "skipped=1") {
		t.Errorf("banner should report 1 skipped, got %q", out)
	}
	if !strings.Contains(out, "re-applying anyway") {
		t.Errorf("banner should explain we're proceeding anyway, got %q", out)
	}
}
