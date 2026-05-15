package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePipfileLock(t *testing.T) {
	content := `{
		"_meta": {"hash": {"sha256": "abc"}},
		"default": {
			"urllib3": {"version": "==1.26.4", "hashes": ["sha256:..."]},
			"Requests": {"version": "==2.25.0"}
		},
		"develop": {
			"pytest": {"version": "==7.4.0"}
		}
	}`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "Pipfile.lock")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parsePipfileLock(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"urllib3":  "1.26.4",
		"requests": "2.25.0", // normalized lowercase
		"pytest":   "7.4.0",
	}
	if len(pkgs) != len(want) {
		t.Fatalf("got %d, want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for _, p := range pkgs {
		w, ok := want[p.Name]
		if !ok || p.Version != w {
			t.Errorf("unexpected %s@%s; want %v", p.Name, p.Version, want)
		}
	}
}

func TestParsePipfileLockSkipsNonExactPins(t *testing.T) {
	content := `{
		"default": {
			"foo": {"version": ">=1.0.0"},
			"bar": {"version": ""}
		}
	}`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "Pipfile.lock")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parsePipfileLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 (no exact pins), got %d: %+v", len(pkgs), pkgs)
	}
}
