package incidents

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDir(t *testing.T) {
	tmp := t.TempDir()

	good := `schema: 1
id: TEST-2026
name: Test incident
severity: high
date: "2026-01-01"
summary: A test
references:
  - "https://example.com"
packages:
  - ecosystem: npm
    name: "foo"
    versions: ["1.0.0"]
file_artifacts:
  - glob: "**/bad.yml"
    severity: critical
    description: A bad file
`
	if err := os.WriteFile(filepath.Join(tmp, "good.yaml"), []byte(good), 0644); err != nil {
		t.Fatal(err)
	}
	noID := `schema: 1
name: missing-id
`
	if err := os.WriteFile(filepath.Join(tmp, "no-id.yaml"), []byte(noID), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "readme.md"), []byte("# ignore"), 0644); err != nil {
		t.Fatal(err)
	}

	incs, err := LoadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(incs) != 1 {
		t.Fatalf("expected 1 incident, got %d: %+v", len(incs), incs)
	}
	if incs[0].ID != "TEST-2026" {
		t.Errorf("wrong ID: %s", incs[0].ID)
	}
	if len(incs[0].Packages) != 1 || incs[0].Packages[0].Name != "foo" {
		t.Errorf("packages: %+v", incs[0].Packages)
	}
	if len(incs[0].FileArtifacts) != 1 || incs[0].FileArtifacts[0].Glob != "**/bad.yml" {
		t.Errorf("artifacts: %+v", incs[0].FileArtifacts)
	}
}

func TestResolveDir(t *testing.T) {
	tmp := t.TempDir()
	got := ResolveDir([]string{"", "/does/not/exist", tmp})
	if got != tmp {
		t.Errorf("got %q, want %q", got, tmp)
	}
	if got := ResolveDir([]string{"", "/none/here/either"}); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}
