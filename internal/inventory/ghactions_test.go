package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGHActionsWorkflow(t *testing.T) {
	content := `name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
      - uses: a/b@0123456789abcdef0123456789abcdef01234567
      - run: echo "no uses"
  call-reusable:
    uses: org/repo/.github/workflows/reusable.yml@v1
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "ci.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseGHActionsWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if p, ok := byName["actions/checkout"]; !ok || p.Version != "v3" {
		t.Errorf("checkout missing or wrong version: %+v", p)
	}
	if p, ok := byName["a/b"]; !ok || !p.Pinned {
		t.Errorf("a/b should be pinned to a 40-char SHA: %+v", p)
	}
	if p, ok := byName["actions/setup-node"]; !ok || p.Pinned {
		t.Errorf("setup-node should not be pinned: %+v", p)
	}
	if _, ok := byName["org/repo/.github/workflows/reusable.yml"]; !ok {
		t.Errorf("reusable workflow ref not captured; have %v", byName)
	}
}
