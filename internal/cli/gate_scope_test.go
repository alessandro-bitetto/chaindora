package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoveManagedShimsMigration(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"npm":      "#!/bin/sh\n# chdora gate shim\n",
		"uv.cmd":   "@REM chdora gate shim\r\n",
		"bundle":   "#!/bin/sh\n# chdora gate shim\n",
		"mvn.cmd":  "@REM chdora gate shim\r\n",
		"composer": "#!/bin/sh\necho user-owned wrapper\n",
		"notes":    "keep this file",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "gradle"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(target, []byte("# chdora gate shim\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	hasSymlink := os.Symlink(target, filepath.Join(dir, "pod")) == nil

	removed, err := removeManagedShims(dir, true)
	if err != nil || removed != 2 {
		t.Fatalf("migration removed=%d err=%v", removed, err)
	}
	for _, name := range []string{"bundle", "mvn.cmd"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("retired %s remains: %v", name, err)
		}
	}
	for _, name := range []string{"npm", "uv.cmd", "composer", "notes", "gradle"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("preserve %s: %v", name, err)
		}
	}
	if hasSymlink {
		if _, err := os.Lstat(filepath.Join(dir, "pod")); err != nil {
			t.Errorf("symlink removed: %v", err)
		}
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("external target touched: %v", err)
	}
	removed, err = removeManagedShims(dir, true)
	if err != nil || removed != 0 {
		t.Fatalf("repeat migration removed=%d err=%v", removed, err)
	}
	removed, err = removeManagedShims(dir, false)
	if err != nil || removed != 2 {
		t.Fatalf("disable removed=%d err=%v", removed, err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "composer")); err != nil || string(data) != files["composer"] {
		t.Fatalf("custom wrapper changed: %q %v", data, err)
	}
}

func TestGateScope(t *testing.T) {
	want := []string{"npm", "yarn", "pnpm", "bun", "deno", "pip", "pip3", "poetry", "uv", "pipenv", "pdm", "dotnet", "paket", "go", "cargo"}
	if len(shimManagers) != len(want) || len(pmClassifiers) != len(want) {
		t.Fatal("shim and dispatcher scope differ")
	}
	shims := map[string]bool{}
	for _, pm := range shimManagers {
		shims[pm] = true
	}
	for _, pm := range want {
		if !shims[pm] || !isGatedPM(pm) {
			t.Errorf("supported manager missing: %s", pm)
		}
	}
	// An empty PATH proves unsupported managers are refused before binary lookup
	// or execution. Retired integrations must not silently pass through.
	t.Setenv("PATH", t.TempDir())
	for _, pm := range []string{"bundle", "mvn", "gradle", "composer", "conda", "brew", "pod", "unknown"} {
		err := gateExecCmd.RunE(gateExecCmd, []string{pm, "install", "example"})
		if err == nil || !strings.Contains(err.Error(), "unsupported package manager") {
			t.Errorf("%s: %v", pm, err)
		}
	}
}

func TestPackageScopeAndAliases(t *testing.T) {
	for _, tc := range []struct{ arg, ecosystem, want string }{
		{"golang.org/x/text@v0.28.0", "go", "go"},
		{"pkg:golang/golang.org/x/text@v0.28.0", "npm", "go"},
		{"serde@1.0.219", "rust", "crates"},
		{"cargo:serde@1.0.219", "npm", "crates"},
		{"Newtonsoft.Json@13.0.3", "dotnet", "nuget"},
		{"requests@2.32.3", "pip", "pypi"},
	} {
		ref, err := parsePackageArg(tc.arg, tc.ecosystem)
		if err != nil || ref.Ecosystem != tc.want {
			t.Errorf("%s/%s: %+v %v", tc.ecosystem, tc.arg, ref, err)
		}
	}
	for _, ecosystem := range []string{"rubygems", "maven", "packagist", "conda", "pub"} {
		for _, arg := range []string{"example@1.0", "pkg:" + ecosystem + "/example@1.0", ecosystem + ":example@1.0"} {
			defaultEcosystem := ecosystem
			if strings.Contains(arg, ":") {
				defaultEcosystem = "npm"
			}
			if _, err := parsePackageArg(arg, defaultEcosystem); err == nil {
				t.Errorf("accepted retired ecosystem %s: %s", ecosystem, arg)
			}
		}
	}
}

func TestGateExecHelpBeforeManager(t *testing.T) {
	var output bytes.Buffer
	previous := gateExecCmd.OutOrStdout()
	gateExecCmd.SetOut(&output)
	defer gateExecCmd.SetOut(previous)
	for _, flag := range []string{"--help", "-h"} {
		output.Reset()
		if err := gateExecCmd.RunE(gateExecCmd, []string{flag}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "Other managers are refused") || !strings.Contains(output.String(), "npm ci") {
			t.Fatalf("help must explain scope and coverage: %s", output.String())
		}
	}
}

func TestProjectDiscoveryScope(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"pdm.lock", "deno.lock", "packages.lock.json", "paket.lock", "Cargo.lock", "App.csproj", "Lib.fsproj", "App.vbproj"} {
		if !isProjectMarker(name) {
			t.Errorf("missing project marker: %s", name)
		}
	}
	for _, name := range []string{"Gemfile", "pom.xml", "build.gradle", "composer.json", "pubspec.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if roots := discoverProjects(dir, nil, false); len(roots) != 0 {
		t.Errorf("retired projects discovered: %v", roots)
	}
}
