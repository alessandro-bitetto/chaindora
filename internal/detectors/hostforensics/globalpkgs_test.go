package hostforensics

import (
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

func TestParseNPMGlobalOutput(t *testing.T) {
	out := `{
		"name": "lib",
		"version": "1.0.0",
		"dependencies": {
			"lodash": {"version": "4.17.21"},
			"@scope/tool": {"version": "2.0.0"},
			"npm": {"version": "10.5.0"},
			"empty-version-skipped": {"version": ""}
		}
	}`
	got, err := parseNPMGlobalOutput([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 packages (one with empty version dropped), got %d: %+v", len(got), got)
	}
	byName := map[string]string{}
	for _, p := range got {
		byName[p.Name] = p.Version
		if p.Ecosystem != inventory.EcosystemNPM {
			t.Errorf("%s wrong ecosystem: %s", p.Name, p.Ecosystem)
		}
		if p.SourcePath != "npm:global" {
			t.Errorf("%s wrong source path: %s", p.Name, p.SourcePath)
		}
	}
	if byName["lodash"] != "4.17.21" || byName["@scope/tool"] != "2.0.0" || byName["npm"] != "10.5.0" {
		t.Errorf("missing/wrong versions: %v", byName)
	}
}

func TestParsePipGlobalOutput(t *testing.T) {
	out := `[
		{"name": "requests", "version": "2.31.0"},
		{"name": "Pillow", "version": "10.0.0"},
		{"name": "foo_bar.baz", "version": "1.0.0"}
	]`
	got, err := parsePipGlobalOutput([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 packages, got %d: %+v", len(got), got)
	}
	byName := map[string]string{}
	for _, p := range got {
		byName[p.Name] = p.Version
		if p.Ecosystem != inventory.EcosystemPyPI {
			t.Errorf("%s wrong ecosystem: %s", p.Name, p.Ecosystem)
		}
	}
	if byName["requests"] != "2.31.0" {
		t.Errorf("missing requests: %v", byName)
	}
	if byName["pillow"] != "10.0.0" {
		t.Errorf("Pillow not normalized to pillow: %v", byName)
	}
	if byName["foo-bar-baz"] != "1.0.0" {
		t.Errorf("foo_bar.baz not normalized to foo-bar-baz: %v", byName)
	}
}

func TestParseNPMGlobalEmpty(t *testing.T) {
	// npm sometimes emits {"dependencies": {}}; should return empty slice, not nil error.
	pkgs, err := parseNPMGlobalOutput([]byte(`{"dependencies": {}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestParseNPMGlobalMalformedJSON(t *testing.T) {
	_, err := parseNPMGlobalOutput([]byte(`{not json`))
	if err == nil {
		t.Error("expected JSON error, got nil")
	}
}
