package cli

import (
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

func TestGroupForRender(t *testing.T) {
	fs := []findings.Finding{
		// Same incident + same PURL across two source paths → 1 group, 2 sources.
		{VulnID: "INC-1", PURL: "pkg:npm/foo@1.0.0", SourcePath: "/a/pkg-lock", Severity: findings.SeverityCritical},
		{VulnID: "INC-1", PURL: "pkg:npm/foo@1.0.0", SourcePath: "/b/pkg-lock", Severity: findings.SeverityCritical},
		// Same VulnID but different PURL → separate group.
		{VulnID: "INC-1", PURL: "pkg:npm/bar@2.0.0", SourcePath: "/c/pkg-lock", Severity: findings.SeverityCritical},
		// File-artifact match (no PURL, distinct paths) → groups by VulnID
		// since PURL is empty for both.
		{VulnID: "INC-2", SourcePath: "/x/worm.yml", Severity: findings.SeverityHigh},
		{VulnID: "INC-2", SourcePath: "/y/worm.yml", Severity: findings.SeverityHigh},
		// Duplicate of the first finding (same VulnID, PURL, AND path) → dropped from sources.
		{VulnID: "INC-1", PURL: "pkg:npm/foo@1.0.0", SourcePath: "/a/pkg-lock", Severity: findings.SeverityCritical},
	}
	groups := groupForRender(fs)
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d: %+v", len(groups), groups)
	}
	// Group 0: INC-1 + foo, 2 distinct sources (the duplicate dropped)
	if len(groups[0].Sources) != 2 {
		t.Errorf("foo group: expected 2 sources, got %d: %v", len(groups[0].Sources), groups[0].Sources)
	}
	// Sources should be sorted
	if groups[0].Sources[0] != "/a/pkg-lock" || groups[0].Sources[1] != "/b/pkg-lock" {
		t.Errorf("foo group: sources not sorted: %v", groups[0].Sources)
	}
	// Group 1: INC-1 + bar
	if groups[1].PURL != "pkg:npm/bar@2.0.0" || len(groups[1].Sources) != 1 {
		t.Errorf("bar group: unexpected shape: %+v", groups[1])
	}
	// Group 2: INC-2 file artifacts (no PURL)
	if groups[2].VulnID != "INC-2" || len(groups[2].Sources) != 2 {
		t.Errorf("INC-2 group: unexpected shape: %+v", groups[2])
	}
}

func TestGroupForRenderEmpty(t *testing.T) {
	if groupForRender(nil) == nil {
		// Empty result is fine; nil also fine.
	}
	if got := groupForRender([]findings.Finding{}); len(got) != 0 {
		t.Errorf("empty input → empty output, got %d groups", len(got))
	}
}
