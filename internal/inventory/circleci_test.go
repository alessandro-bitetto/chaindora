package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCircleCIConfig(t *testing.T) {
	content := `version: 2.1

orbs:
  aws-s3: circleci/aws-s3@3.0.0
  node: circleci/node@5.1.0
  slack: circleci/slack@volatile

jobs:
  build:
    docker:
      - image: cimg/node:20.0
    steps:
      - checkout
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseCircleCIConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"circleci/aws-s3": "3.0.0",
		"circleci/node":   "5.1.0",
		"circleci/slack":  "volatile",
	}
	if len(pkgs) != len(want) {
		t.Fatalf("got %d, want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for _, p := range pkgs {
		w, ok := want[p.Name]
		if !ok || p.Version != w {
			t.Errorf("unexpected %s@%s; want %v", p.Name, p.Version, want)
		}
		if p.Ecosystem != EcosystemCircleCIOrbs {
			t.Errorf("wrong ecosystem: %q", p.Ecosystem)
		}
	}
}
