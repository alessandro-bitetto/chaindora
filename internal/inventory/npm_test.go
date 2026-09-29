package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseNPMPackageLockV3(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "package-lock.json")
	content := `{
		"name": "test",
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "test", "version": "1.0.0"},
			"node_modules/foo": {"version": "1.2.3"},
			"node_modules/@scope/bar": {"version": "0.0.1"},
			"node_modules/foo/node_modules/nested-dep": {"version": "9.9.9"}
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseNPMPackageLock(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"foo":        "1.2.3",
		"@scope/bar": "0.0.1",
		"nested-dep": "9.9.9",
	}
	if len(pkgs) != len(want) {
		t.Fatalf("expected %d packages, got %d: %+v", len(want), len(pkgs), pkgs)
	}
	for _, p := range pkgs {
		w, ok := want[p.Name]
		if !ok {
			t.Errorf("unexpected: %s@%s", p.Name, p.Version)
			continue
		}
		if p.Version != w {
			t.Errorf("%s: got %s, want %s", p.Name, p.Version, w)
		}
		if p.Ecosystem != EcosystemNPM {
			t.Errorf("%s: wrong ecosystem %q", p.Name, p.Ecosystem)
		}
	}
}

func TestParseNPMPackageLockV1(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "package-lock.json")
	content := `{
		"name": "test",
		"lockfileVersion": 1,
		"dependencies": {
			"foo": {
				"version": "1.2.3",
				"dependencies": {
					"nested": {"version": "0.0.1"}
				}
			}
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseNPMPackageLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d: %+v", len(pkgs), pkgs)
	}
}

func TestParseNPMPackageLockDedupes(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "package-lock.json")
	content := `{
		"name": "test",
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "test", "version": "1.0.0"},
			"node_modules/foo": {"version": "1.2.3"},
			"node_modules/bar/node_modules/foo": {"version": "1.2.3"}
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseNPMPackageLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Errorf("expected dedup to 1 package, got %d: %+v", len(pkgs), pkgs)
	}
}
