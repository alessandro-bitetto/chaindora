package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseUVLock(t *testing.T) {
	content := `version = 1

[[package]]
name = "urllib3"
version = "2.0.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "Requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "uv.lock")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseUVLock(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"urllib3":  "2.0.4",
		"requests": "2.31.0",
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
