package findings

import (
	"bytes"
	"strings"
	"testing"
)

func TestEmitGitHubAnnotations(t *testing.T) {
	fs := []Finding{
		{
			Detector: "osv-ioc",
			Name:     "lodash",
			VulnID:   "GHSA-1",
			Summary:  "Command Injection",
			Severity: SeverityHigh,
			SourcePath: "package-lock.json",
		},
		{
			Detector: "incident-pack",
			VulnID:   "I-1",
			Summary:  "Some\nmultiline\nsummary",
			Severity: SeverityMedium,
			SourcePath: "",
		},
		{
			Detector: "hostforensics:tokens",
			VulnID:   "T-1",
			Summary:  "Token present",
			Severity: SeverityLow,
			SourcePath: "/home/u/.npmrc",
		},
	}
	var buf bytes.Buffer
	if err := EmitGitHubAnnotations(&buf, fs); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 annotation lines, got %d:\n%s", len(lines), buf.String())
	}
	if !strings.HasPrefix(lines[0], "::error file=package-lock.json,line=1::") {
		t.Errorf("line 0 not formatted as error: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "::warning::") {
		t.Errorf("line 1 (no source) should be plain ::warning:: : %q", lines[1])
	}
	if !strings.Contains(lines[1], "%0A") {
		t.Errorf("line 1 newlines not escaped: %q", lines[1])
	}
	if !strings.HasPrefix(lines[2], "::notice file=/home/u/.npmrc,line=1::") {
		t.Errorf("line 2 not formatted as notice: %q", lines[2])
	}
}

func TestEscapeAnnotation(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"hello", "hello"},
		{"line1\nline2", "line1%0Aline2"},
		{"with\rCR", "with%0DCR"},
		{"100%", "100%25"},
		{"both %0A inside", "both %250A inside"}, // % gets escaped first, then the newline isn't there
	}
	for _, c := range cases {
		if got := escapeAnnotation(c.in); got != c.want {
			t.Errorf("escapeAnnotation(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
