package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

func TestDetectorTallyEnableThenAbsorb(t *testing.T) {
	tt := newDetectorTally()
	tt.Enable("hostforensics")
	tt.Enable("incident-pack")
	tt.AbsorbFindings([]findings.Finding{
		{Detector: "osv-ioc", Severity: findings.SeverityHigh},
		{Detector: "osv-ioc", Severity: findings.SeverityMedium},
		{Detector: "heuristic:dep-confusion"},
		{Detector: "incident-pack"},
	})
	if tt.counts["hostforensics"] != 0 {
		t.Errorf("hostforensics should remain 0, got %d", tt.counts["hostforensics"])
	}
	if tt.counts["osv-ioc"] != 2 {
		t.Errorf("osv-ioc: %d, want 2", tt.counts["osv-ioc"])
	}
	if tt.counts["heuristic"] != 1 {
		t.Errorf("heuristic: %d, want 1 (sub-detector folded into family)", tt.counts["heuristic"])
	}
	if tt.counts["incident-pack"] != 1 {
		t.Errorf("incident-pack: %d, want 1", tt.counts["incident-pack"])
	}
}

func TestDetectorTallyWriteTo(t *testing.T) {
	tt := newDetectorTally()
	tt.Enable("hostforensics")
	tt.Enable("incident-pack")
	tt.AbsorbFindings([]findings.Finding{
		{Detector: "osv-ioc"},
		{Detector: "osv-ioc"},
		{Detector: "osv-ioc"},
		{Detector: "heuristic:typosquat"},
		{Detector: "incident-pack"},
	})
	var buf bytes.Buffer
	tt.Print(&buf)
	out := buf.String()
	// All four detector classes should be listed.
	for _, want := range []string{"osv-ioc", "incident-pack", "heuristic", "host-state"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// Total should appear.
	if !strings.Contains(out, "total") || !strings.Contains(out, "5 findings") {
		t.Errorf("output should show total of 5 findings, got:\n%s", out)
	}
}

func TestClassifyDetector(t *testing.T) {
	cases := map[string]string{
		"osv-ioc":                  "osv-ioc",
		"incident-pack":            "incident-pack",
		"heuristic:dep-confusion":  "heuristic",
		"heuristic:typosquat":      "heuristic",
		"hostforensics:tokens":     "hostforensics",
		"hostforensics:persistence": "hostforensics",
	}
	for in, want := range cases {
		if got := classifyDetector(in); got != want {
			t.Errorf("classifyDetector(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDetectorTallyEmptyNoOutput(t *testing.T) {
	tt := newDetectorTally()
	var buf bytes.Buffer
	tt.Print(&buf)
	if buf.Len() != 0 {
		t.Errorf("empty tally should emit nothing, got %q", buf.String())
	}
}
