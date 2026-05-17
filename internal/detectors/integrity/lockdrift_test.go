package integrity

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// TestLockDrift_VersionMismatch — package-lock.json pins one version,
// node_modules/<name>/package.json reports a different one. This is
// the "directory was replaced post-install" case, the headline
// scenario the lockfile-vs-disk check exists to detect.
func TestLockDrift_VersionMismatch(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package-lock.json"), `{
	  "name": "test", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "test", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.21", "integrity": "sha512-AAA"}
	  }
	}`)
	mustWrite(t, filepath.Join(dir, "node_modules", "lodash", "package.json"), `{
	  "name": "lodash",
	  "version": "4.17.20"
	}`)

	d := New([]string{dir})
	out, _ := d.Detect(context.Background())
	if !anyDetector(out, "integrity:lockfile-vs-disk-version") {
		t.Fatalf("expected version-drift finding, got: %+v", out)
	}
}

// TestLockDrift_NameMismatch — node_modules/<name>/package.json
// reports a different `name`. Means the directory was replaced
// wholesale (symlink swap, manual edit, malicious extractor).
func TestLockDrift_NameMismatch(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package-lock.json"), `{
	  "name": "test", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "test", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.21"}
	  }
	}`)
	mustWrite(t, filepath.Join(dir, "node_modules", "lodash", "package.json"), `{
	  "name": "evil-lodash",
	  "version": "4.17.21"
	}`)

	d := New([]string{dir})
	out, _ := d.Detect(context.Background())
	if !anyDetector(out, "integrity:lockfile-vs-disk-name") {
		t.Fatalf("expected name-drift finding, got: %+v", out)
	}
}

// TestLockDrift_MirrorIntegrityDrift — project lockfile records one
// integrity, the install-mirror node_modules/.package-lock.json
// records a different one. Means one lockfile was modified without
// the other.
func TestLockDrift_MirrorIntegrityDrift(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package-lock.json"), `{
	  "name": "test", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "test", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.21", "integrity": "sha512-AAA"}
	  }
	}`)
	mustWrite(t, filepath.Join(dir, "node_modules", "lodash", "package.json"), `{
	  "name": "lodash",
	  "version": "4.17.21"
	}`)
	mustWrite(t, filepath.Join(dir, "node_modules", ".package-lock.json"), `{
	  "name": "test", "lockfileVersion": 3,
	  "packages": {
	    "node_modules/lodash": {"version": "4.17.21", "integrity": "sha512-BBB"}
	  }
	}`)

	d := New([]string{dir})
	out, _ := d.Detect(context.Background())
	if !anyDetector(out, "integrity:lockfile-mirror-drift") {
		t.Fatalf("expected mirror-drift finding, got: %+v", out)
	}
}

// TestLockDrift_NestedDepsNoFalsePositive — regression test for the
// v0.15.0 bug that produced thousands of false-positive drift findings.
// When a lockfile pins multiple versions of the same package at
// different nested paths (typical for transitive deps like semver,
// brace-expansion, minimatch), the v0.15.0 code mis-reported every
// non-hoisted entry as drift because it checked the top-level
// node_modules/<name>/ for every lockfile key, regardless of the
// lockfile-recorded install path.
//
// Fix: walk the EXACT lockfile path for each entry. semver pinned at
// `node_modules/foo/node_modules/semver` is checked AT that path,
// not at top-level.
func TestLockDrift_NestedDepsNoFalsePositive(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package-lock.json"), `{
	  "name": "test", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "test", "version": "1.0.0"},
	    "node_modules/semver": {"version": "7.6.0"},
	    "node_modules/eslint/node_modules/semver": {"version": "5.7.2"},
	    "node_modules/eslint": {"version": "8.0.0"}
	  }
	}`)
	// Top-level semver is the hoisted version 7.6.0.
	mustWrite(t, filepath.Join(dir, "node_modules", "semver", "package.json"), `{
	  "name": "semver", "version": "7.6.0"
	}`)
	// eslint's nested copy of semver is 5.7.2.
	mustWrite(t, filepath.Join(dir, "node_modules", "eslint", "node_modules", "semver", "package.json"), `{
	  "name": "semver", "version": "5.7.2"
	}`)
	mustWrite(t, filepath.Join(dir, "node_modules", "eslint", "package.json"), `{
	  "name": "eslint", "version": "8.0.0"
	}`)

	d := New([]string{dir})
	out, _ := d.Detect(context.Background())
	for _, f := range out {
		if f.Detector == "integrity:lockfile-vs-disk-version" ||
			f.Detector == "integrity:lockfile-vs-disk-name" {
			t.Errorf("did not expect drift finding when nested deps match their pinned paths: %+v", f)
		}
	}
}

// TestLockDrift_NestedRealDriftStillFires — verifies the fix doesn't
// silence GENUINE drift at a nested path. If `node_modules/foo/
// node_modules/semver` reports a version different from the
// lockfile's pin AT THAT PATH, drift should still fire.
func TestLockDrift_NestedRealDriftStillFires(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package-lock.json"), `{
	  "name": "test", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "test", "version": "1.0.0"},
	    "node_modules/eslint/node_modules/semver": {"version": "5.7.2"}
	  }
	}`)
	// Genuine drift: lockfile pins 5.7.2 at the nested path, disk has 6.0.0 there.
	mustWrite(t, filepath.Join(dir, "node_modules", "eslint", "node_modules", "semver", "package.json"), `{
	  "name": "semver", "version": "6.0.0"
	}`)

	d := New([]string{dir})
	out, _ := d.Detect(context.Background())
	if !anyDetector(out, "integrity:lockfile-vs-disk-version") {
		t.Fatalf("expected drift finding for genuine nested-path mismatch, got %d findings", len(out))
	}
}

// TestLockDrift_YarnPnpmMultiVersionSilent — when yarn or pnpm
// lockfile pins multiple versions of the same package, the
// top-level on-disk version need only match ONE of them for the
// check to stay silent. Same false-positive class as the npm bug.
func TestLockDrift_YarnPnpmMultiVersionSilent(t *testing.T) {
	dir := t.TempDir()
	// yarn.lock v1 with two versions of semver — both legitimately pinned.
	mustWrite(t, filepath.Join(dir, "yarn.lock"), `# yarn lockfile v1

semver@^5.0.0:
  version "5.7.2"
  resolved "https://registry.yarnpkg.com/semver/-/semver-5.7.2.tgz"

semver@^7.0.0:
  version "7.6.0"
  resolved "https://registry.yarnpkg.com/semver/-/semver-7.6.0.tgz"
`)
	// Top-level on disk: 7.6.0 (the hoisted version).
	mustWrite(t, filepath.Join(dir, "node_modules", "semver", "package.json"), `{
	  "name": "semver", "version": "7.6.0"
	}`)

	d := New([]string{dir})
	out, _ := d.Detect(context.Background())
	for _, f := range out {
		if f.Detector == "integrity:lockfile-vs-disk-version" {
			t.Errorf("did not expect drift for multi-version yarn lockfile where disk matches a pinned version: %+v", f)
		}
	}
}

// TestLockDrift_CleanProjectIsSilent — matching lockfile + on-disk
// version + identical mirror lockfile should produce zero findings.
// The check has to stay silent on the happy path or it'll drown out
// real signals.
func TestLockDrift_CleanProjectIsSilent(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package-lock.json"), `{
	  "name": "test", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "test", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.21", "integrity": "sha512-AAA"}
	  }
	}`)
	mustWrite(t, filepath.Join(dir, "node_modules", "lodash", "package.json"), `{
	  "name": "lodash",
	  "version": "4.17.21"
	}`)
	mustWrite(t, filepath.Join(dir, "node_modules", ".package-lock.json"), `{
	  "packages": {
	    "node_modules/lodash": {"version": "4.17.21", "integrity": "sha512-AAA"}
	  }
	}`)

	d := New([]string{dir})
	out, _ := d.Detect(context.Background())
	for _, f := range out {
		if f.Detector == "integrity:lockfile-vs-disk-version" ||
			f.Detector == "integrity:lockfile-vs-disk-name" ||
			f.Detector == "integrity:lockfile-mirror-drift" {
			t.Errorf("did not expect %s on clean project: %+v", f.Detector, f)
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func anyDetector(out []findings.Finding, want string) bool {
	for _, f := range out {
		if f.Detector == want {
			return true
		}
	}
	return false
}
