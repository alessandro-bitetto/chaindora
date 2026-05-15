package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGoMod(t *testing.T) {
	content := `module github.com/example/foo

go 1.22

require github.com/single/dep v1.0.0

require (
	github.com/spf13/cobra v1.10.2
	github.com/gopkg.in/yaml.v3 v3.0.1
	github.com/some/dep v0.0.0-20240101000000-abcdef123456 // indirect
)

require (
	github.com/another/dep v2.3.4 // indirect
)

// commented out, ignore
// require github.com/should-skip/dep v9.9.9
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "go.mod")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseGoMod(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"github.com/single/dep":     "v1.0.0",
		"github.com/spf13/cobra":    "v1.10.2",
		"github.com/gopkg.in/yaml.v3": "v3.0.1",
		"github.com/some/dep":       "v0.0.0-20240101000000-abcdef123456",
		"github.com/another/dep":    "v2.3.4",
	}
	if len(pkgs) != len(want) {
		t.Fatalf("expected %d packages, got %d: %+v", len(want), len(pkgs), pkgs)
	}
	for _, p := range pkgs {
		w, ok := want[p.Name]
		if !ok {
			t.Errorf("unexpected package: %s@%s", p.Name, p.Version)
			continue
		}
		if p.Version != w {
			t.Errorf("%s: got version %s, want %s", p.Name, p.Version, w)
		}
		if p.Ecosystem != EcosystemGoModules {
			t.Errorf("%s: wrong ecosystem %q", p.Name, p.Ecosystem)
		}
	}
}
