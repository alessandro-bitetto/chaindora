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

// TestGradleManifest_ParsesGroovyAndKotlinDSL verifies the
// gradle build-file parser handles both DSL flavors.
func TestGradleManifest_ParsesGroovyAndKotlinDSL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "build.gradle")
	mustWriteInventory(t, path, `
dependencies {
    implementation 'com.google.guava:guava:32.1.3-jre'
    implementation "org.jetbrains.kotlin:kotlin-stdlib:1.9.0"
    testImplementation("io.mockk:mockk:1.13.8")
    runtimeOnly 'ch.qos.logback:logback-classic:1.4.14'
    api "org.springframework.boot:spring-boot:$springVersion"  // skipped — interpolation
}
`)
	pkgs, err := parseGradleManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{
		"com.google.guava:guava",
		"org.jetbrains.kotlin:kotlin-stdlib",
		"io.mockk:mockk",
		"ch.qos.logback:logback-classic",
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	for _, want := range wantNames {
		if _, ok := byName[want]; !ok {
			t.Errorf("missing expected dep: %s (got %+v)", want, pkgs)
		}
	}
	// Spring-boot dep was string-interpolated — version should be
	// empty (we don't have property resolution).
	if springBoot, ok := byName["org.springframework.boot:spring-boot"]; ok {
		if springBoot.Version != "" {
			t.Errorf("interpolated version should be empty, got %q", springBoot.Version)
		}
	}
}

// TestComposerJSON_ManifestFallback verifies the composer.json
// fallback parses require / require-dev and skips php + ext-* virtual packages.
func TestComposerJSON_ManifestFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "composer.json")
	mustWriteInventory(t, path, `{
	  "name": "vendor/app",
	  "require": {
	    "php": "^8.1",
	    "ext-mbstring": "*",
	    "symfony/console": "^7.0",
	    "monolog/monolog": "^3.5"
	  },
	  "require-dev": {
	    "phpunit/phpunit": "^11.0"
	  }
	}`)
	pkgs, err := parseComposerJSONManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if _, ok := byName["php"]; ok {
		t.Errorf("should skip php meta-package, got %+v", byName)
	}
	if _, ok := byName["ext-mbstring"]; ok {
		t.Errorf("should skip ext-* virtual packages, got %+v", byName)
	}
	for _, want := range []string{"symfony/console", "monolog/monolog", "phpunit/phpunit"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("missing expected dep: %s (got %+v)", want, pkgs)
		}
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
