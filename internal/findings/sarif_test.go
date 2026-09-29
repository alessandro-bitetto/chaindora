package findings

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

func TestEmitSARIF(t *testing.T) {
	fs := []Finding{
		{
			Detector:   "osv-ioc",
			PURL:       "pkg:npm/lodash@4.17.20",
			Ecosystem:  inventory.EcosystemNPM,
			Name:       "lodash",
			Version:    "4.17.20",
			VulnID:     "GHSA-35jh-r3h4-6jhm",
			Summary:    "Command Injection in lodash",
			Severity:   SeverityHigh,
			References: []string{"https://github.com/advisories/GHSA-35jh-r3h4-6jhm"},
			SourcePath: "testdata/npm/package-lock.json",
		},
		{
			Detector:   "incident-pack",
			PURL:       "pkg:npm/lodash@4.17.20", // same package, different rule
			Ecosystem:  inventory.EcosystemNPM,
			Name:       "lodash",
			Version:    "4.17.20",
			VulnID:     "GHSA-35jh-r3h4-6jhm", // dup with previous — should dedupe to ONE rule
			Summary:    "Command Injection in lodash",
			Severity:   SeverityHigh,
			SourcePath: "testdata/npm/package-lock.json",
		},
		{
			Detector:   "incident-pack",
			VulnID:     "SHAI-HULUD-2025",
			Summary:    "Shai-Hulud worm artifact",
			Severity:   SeverityCritical,
			SourcePath: "testdata/ghactions/.github/workflows/shai-hulud-workflow.yml",
		},
	}

	var buf bytes.Buffer
	if err := EmitSARIF(&buf, fs, "0.1.0"); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", doc["version"])
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected 1 run, got %v", doc["runs"])
	}
	run := runs[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "chaindora" {
		t.Errorf("driver name = %v", driver["name"])
	}
	rules := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Errorf("expected 2 deduplicated rules, got %d: %v", len(rules), rules)
	}
	results := run["results"].([]any)
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
	r0 := results[0].(map[string]any)
	if r0["level"] != "error" {
		t.Errorf("HIGH severity → level=%q, want \"error\"", r0["level"])
	}
}

func TestSARIFLevels(t *testing.T) {
	cases := []struct {
		s    Severity
		want string
	}{
		{SeverityCritical, "error"},
		{SeverityHigh, "error"},
		{SeverityMedium, "warning"},
		{SeverityLow, "note"},
		{SeverityUnknown, "note"},
	}
	for _, c := range cases {
		if got := sarifLevel(c.s); got != c.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", c.s, got, c.want)
		}
	}
}
