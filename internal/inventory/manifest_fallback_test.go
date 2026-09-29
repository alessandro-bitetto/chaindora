package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCsprojManifest_ParsesPackageReferences verifies the .csproj
// fallback extracts NuGet packages from a representative MSBuild
// project file. Covers both `Version="..."` attribute and
// `<Version>...</Version>` child element forms.
func TestCsprojManifest_ParsesPackageReferences(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Frameflows.Core.csproj")
	mustWriteInventory(t, path, `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Microsoft.Extensions.Logging">
      <Version>9.0.0</Version>
    </PackageReference>
    <PackageReference Include="MimeKit" Version="4.14.0" />
    <PackageReference Include="ResolvedFromProperty" Version="$(SomeProp)" />
  </ItemGroup>
</Project>
`)
	pkgs, err := parseCsprojManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 4 {
		t.Errorf("expected 4 packages, got %d: %+v", len(pkgs), pkgs)
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if got := byName["Newtonsoft.Json"].Version; got != "13.0.3" {
		t.Errorf("Newtonsoft.Json version: got %q, want 13.0.3", got)
	}
	if got := byName["Microsoft.Extensions.Logging"].Version; got != "9.0.0" {
		t.Errorf("Logging version (child element): got %q, want 9.0.0", got)
	}
	if got := byName["ResolvedFromProperty"].Version; got != "" {
		t.Errorf("Property-substitution version should be empty, got %q", got)
	}
	if byName["Newtonsoft.Json"].Ecosystem != EcosystemNuGet {
		t.Errorf("ecosystem should be NuGet, got %q", byName["Newtonsoft.Json"].Ecosystem)
	}
}

// TestCsprojManifest_SkipsWhenLockfileSibling verifies the
// inventory dispatcher correctly prefers the real lockfile when
// both packages.lock.json and a .csproj exist in the same dir.
func TestCsprojManifest_SkipsWhenLockfileSibling(t *testing.T) {
	dir := t.TempDir()
	csproj := filepath.Join(dir, "App.csproj")
	mustWriteInventory(t, csproj, `<Project><ItemGroup><PackageReference Include="Foo" Version="1.0" /></ItemGroup></Project>`)
	if hasNuGetLockfileSibling(csproj) {
		t.Errorf("no lockfile yet — should not skip")
	}
	mustWriteInventory(t, filepath.Join(dir, "packages.lock.json"), `{"version":1,"dependencies":{}}`)
	if !hasNuGetLockfileSibling(csproj) {
		t.Errorf("lockfile present — should skip the manifest fallback")
	}
}

// TestPyprojectManifest_PEP621AndPoetry verifies the pyproject.toml
// fallback handles both major dep-declaration styles.
func TestPyprojectManifest_PEP621AndPoetry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")
	mustWriteInventory(t, path, `
[project]
name = "myapp"
version = "0.1.0"
dependencies = [
  "requests>=2.31",
  "rich~=13.0",
  "click ; python_version >= '3.11'",
]

[tool.poetry.dependencies]
python = "^3.11"
django = "^5.0"
celery = {version = "^5.3", optional = true}
`)
	pkgs, err := parsePyprojectManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if _, ok := byName["python"]; ok {
		t.Errorf("should skip python meta-package, got %+v", byName)
	}
	// PEP 621 deps.
	if _, ok := byName["requests"]; !ok {
		t.Errorf("missing requests from PEP 621 deps; got %+v", byName)
	}
	if got := byName["requests"].Version; got != ">=2.31" {
		t.Errorf("requests version constraint: got %q, want >=2.31", got)
	}
	if _, ok := byName["rich"]; !ok {
		t.Errorf("missing rich; got %+v", byName)
	}
	// Poetry deps.
	if _, ok := byName["django"]; !ok {
		t.Errorf("missing django from poetry deps; got %+v", byName)
	}
	if _, ok := byName["celery"]; !ok {
		t.Errorf("missing celery from poetry inline-table dep; got %+v", byName)
	}
}

// TestPyprojectManifest_SkipsWhenLockfileSibling — same precedence
// rule as csproj: real lockfile wins, manifest is fallback only.
func TestPyprojectManifest_SkipsWhenLockfileSibling(t *testing.T) {
	dir := t.TempDir()
	py := filepath.Join(dir, "pyproject.toml")
	mustWriteInventory(t, py, `[project]
name = "x"
dependencies = ["requests>=2"]
`)
	if hasPythonLockSibling(py) {
		t.Errorf("no lockfile — should not skip")
	}
	for _, lockName := range []string{"poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock"} {
		// Create one at a time, verify detected, then remove.
		lp := filepath.Join(dir, lockName)
		mustWriteInventory(t, lp, "")
		if !hasPythonLockSibling(py) {
			t.Errorf("%s present — should skip manifest fallback", lockName)
		}
		os.Remove(lp)
	}
}

func mustWriteInventory(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
