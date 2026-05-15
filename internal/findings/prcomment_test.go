package findings

import (
	"bytes"
	"strings"
	"testing"
)

func TestEmitPRComment_CleanRepo(t *testing.T) {
	var buf bytes.Buffer
	if err := EmitPRComment(&buf, nil, nil, nil, nil, "0.10.0"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "chaindora:pr-comment") {
		t.Errorf("missing sticky-comment marker: %q", out)
	}
	if !strings.Contains(out, "No findings") {
		t.Errorf("clean repo should say so: %q", out)
	}
}

func TestEmitPRComment_NewCriticalsBlock(t *testing.T) {
	current := []Finding{
		{VulnID: "CVE-NEW", Name: "evil", Version: "1.0.0", Severity: SeverityCritical, Detector: "osv-ioc"},
	}
	var buf bytes.Buffer
	if err := EmitPRComment(&buf, current, nil, current, nil, "0.10.0"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "🔴") {
		t.Errorf("critical-new should use red verdict, got %q", out)
	}
	if !strings.Contains(out, "Block on critical/high") {
		t.Errorf("verdict should call for blocking, got %q", out)
	}
	if !strings.Contains(out, "evil@1.0.0") {
		t.Errorf("PR comment must name the package, got %q", out)
	}
}

func TestEmitPRComment_PreExistingButNoNewIsAmber(t *testing.T) {
	old := []Finding{
		{VulnID: "OLD-1", Name: "lodash", Version: "4.17.20", Severity: SeverityMedium, Detector: "osv-ioc"},
	}
	var buf bytes.Buffer
	if err := EmitPRComment(&buf, old, nil, nil, nil, "0.10.0"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "🟡") {
		t.Errorf("pre-existing-only should use amber verdict, got %q", out)
	}
	if !strings.Contains(out, "<details><summary>1 pre-existing") {
		t.Errorf("pre-existing should collapse under <details>, got %q", out)
	}
}

func TestEmitPRComment_SuppressedSurfaced(t *testing.T) {
	supp := []SuppressedFinding{
		{
			Finding:     Finding{VulnID: "CVE-X", Name: "foo", Version: "1.0", Severity: SeverityHigh},
			Suppression: Suppression{Reason: "Known FP", VulnID: "CVE-X"},
			Expired:     false,
		},
	}
	var buf bytes.Buffer
	if err := EmitPRComment(&buf, nil, supp, nil, nil, "0.10.0"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "<details><summary>1 suppressed") {
		t.Errorf("suppressed findings missing from output: %q", out)
	}
	if !strings.Contains(out, "Known FP") {
		t.Errorf("suppression reason should be visible, got %q", out)
	}
}

func TestEmitPRComment_ExpiredSuppressionWarns(t *testing.T) {
	supp := []SuppressedFinding{
		{
			Finding:     Finding{VulnID: "OLD-1", Name: "foo", Version: "1.0", Severity: SeverityMedium},
			Suppression: Suppression{Reason: "Expired entry", VulnID: "OLD-1", Expires: "2020-01-01"},
			Expired:     true,
		},
	}
	var buf bytes.Buffer
	if err := EmitPRComment(&buf, nil, supp, nil, nil, "0.10.0"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "expired suppression") {
		t.Errorf("expired suppression should be called out: %q", out)
	}
}

func TestEscapeMD(t *testing.T) {
	if got := escapeMD("a|b`c\nd"); got != `a\|b'c d` {
		t.Errorf("got %q", got)
	}
}
