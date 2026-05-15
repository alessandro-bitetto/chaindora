package findings

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestEmitJSONL(t *testing.T) {
	fs := []Finding{
		{Detector: "osv-ioc", VulnID: "A", Summary: "a"},
		{Detector: "incident-pack", VulnID: "B", Summary: "b"},
		{Detector: "hostforensics:tokens", VulnID: "C", Summary: "c"},
	}
	var buf bytes.Buffer
	if err := EmitJSONL(&buf, fs); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d:\n%s", len(lines), buf.String())
	}
	for i, line := range lines {
		var f Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Errorf("line %d not valid JSON: %v", i, err)
		}
	}
}

func TestEmitJSONLEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := EmitJSONL(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %q", buf.String())
	}
}
