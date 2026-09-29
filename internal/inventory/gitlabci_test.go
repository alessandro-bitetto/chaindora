package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGitLabCI(t *testing.T) {
	content := `include:
  - local: '/templates/local.yml'
  - project: 'group/security-templates'
    ref: 'v2.5.0'
    file: '/templates/SAST.gitlab-ci.yml'
  - template: 'Auto-DevOps.gitlab-ci.yml'
  - remote: 'https://example.invalid/pipeline.yml'

stages:
  - build

build:
  script:
    - echo build
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".gitlab-ci.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseGitLabCI(path)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if p, ok := byName["group/security-templates"]; !ok || p.Version != "v2.5.0" {
		t.Errorf("missing or wrong project include: %+v", p)
	}
	if _, ok := byName["template:Auto-DevOps.gitlab-ci.yml"]; !ok {
		t.Errorf("missing template include; got %v", byName)
	}
	if _, ok := byName["remote:https://example.invalid/pipeline.yml"]; !ok {
		t.Errorf("missing remote include; got %v", byName)
	}
	for _, p := range pkgs {
		if p.Ecosystem != EcosystemGitLabCI {
			t.Errorf("wrong ecosystem on %s: %q", p.Name, p.Ecosystem)
		}
	}
}
