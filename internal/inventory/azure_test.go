package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAzurePipelines(t *testing.T) {
	content := `trigger:
  - main

pool:
  vmImage: ubuntu-latest

stages:
  - stage: Build
    jobs:
      - job: Build
        steps:
          - task: NodeTool@0
            inputs:
              versionSpec: '20.x'
          - task: Npm@1
            inputs:
              command: install
          - task: PublishBuildArtifacts@1
          - script: echo "not a task"
          - task: NodeTool@0  # dup, should dedupe
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "azure-pipelines.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseAzurePipelines(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"NodeTool":              "0",
		"Npm":                   "1",
		"PublishBuildArtifacts": "1",
	}
	if len(pkgs) != len(want) {
		t.Fatalf("got %d, want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for _, p := range pkgs {
		w, ok := want[p.Name]
		if !ok || p.Version != w {
			t.Errorf("unexpected %s@%s; want %v", p.Name, p.Version, want)
		}
		if p.Ecosystem != EcosystemAzurePipelines {
			t.Errorf("wrong ecosystem: %q", p.Ecosystem)
		}
	}
}
