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

// TestLockDrift_AliasNoFalsePositive — an aliased install (the
// `string-width-cjs` → `string-width` pattern shipped by @isaacs/cliui
// and used transitively by npm, eslint, etc.) legitimately has a
// directory name that differs from the package's real name. npm records
// the resolved target on the lockfile entry (`"name":"string-width"`),
// so the on-disk package.json matching that target is NOT drift. The
// pre-fix detector compared against the key-derived name and screamed
// CRITICAL on every aliased dependency.
func TestLockDrift_AliasNoFalsePositive(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package-lock.json"), `{
	  "name": "test", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "test", "version": "1.0.0"},
	    "node_modules/string-width-cjs": {"name": "string-width", "version": "4.2.3"}
	  }
	}`)
	mustWrite(t, filepath.Join(dir, "node_modules", "string-width-cjs", "package.json"), `{
	  "name": "string-width",
	  "version": "4.2.3"
	}`)

	d := New([]string{dir})
	out, _ := d.Detect(context.Background())
	if anyDetector(out, "integrity:lockfile-vs-disk-name") {
		t.Fatalf("aliased install must not produce a name-drift finding, got: %+v", out)
	}
}

// TestLockDrift_AliasSwapStillFires — the attacker's evasion path is
// closed: even though string-width-cjs is an alias, a directory whose
// package.json name does NOT match the lockfile-declared target
// (`string-width`) still trips the detector. Suppression that survives
// this test is suppression that doesn't create a blind spot.
func TestLockDrift_AliasSwapStillFires(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package-lock.json"), `{
	  "name": "test", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "test", "version": "1.0.0"},
	    "node_modules/string-width-cjs": {"name": "string-width", "version": "4.2.3"}
	  }
	}`)
	mustWrite(t, filepath.Join(dir, "node_modules", "string-width-cjs", "package.json"), `{
	  "name": "evil",
	  "version": "4.2.3"
	}`)

	d := New([]string{dir})
	out, _ := d.Detect(context.Background())
	if !anyDetector(out, "integrity:lockfile-vs-disk-name") {
		t.Fatalf("a swapped alias directory (disk name ≠ declared target) must still fire, got: %+v", out)
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

// findingByDetector returns the first finding from the given detector.
func findingByDetector(out []findings.Finding, det string) (findings.Finding, bool) {
	for _, f := range out {
		if f.Detector == det {
			return f, true
		}
	}
	return findings.Finding{}, false
}

// TestLockDrift_YarnAliasNoFalsePositive — the yarn equivalent of the
// npm alias case: `string-width-cjs@npm:string-width@…` installs under
// the alias dir but its package.json reports the real name. With the
// alias target threaded through, this is no longer a name-drift.
func TestLockDrift_YarnAliasNoFalsePositive(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "yarn.lock"), `# yarn lockfile v1

string-width-cjs@npm:string-width@^4.2.0:
  version "4.2.3"
  resolved "https://registry.yarnpkg.com/string-width/-/string-width-4.2.3.tgz"
`)
	mustWrite(t, filepath.Join(dir, "node_modules", "string-width-cjs", "package.json"), `{
	  "name": "string-width", "version": "4.2.3"
	}`)

	out, _ := New([]string{dir}).Detect(context.Background())
	if anyDetector(out, "integrity:lockfile-vs-disk-name") {
		t.Fatalf("yarn aliased install must not produce a name-drift finding, got: %+v", out)
	}
}

// TestLockDrift_YarnAliasSwapStillFires — evasion path closed for yarn
// too: a directory whose package.json name ≠ the declared alias target
// still fires.
func TestLockDrift_YarnAliasSwapStillFires(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "yarn.lock"), `# yarn lockfile v1

string-width-cjs@npm:string-width@^4.2.0:
  version "4.2.3"
  resolved "https://registry.yarnpkg.com/string-width/-/string-width-4.2.3.tgz"
`)
	mustWrite(t, filepath.Join(dir, "node_modules", "string-width-cjs", "package.json"), `{
	  "name": "evil", "version": "4.2.3"
	}`)

	out, _ := New([]string{dir}).Detect(context.Background())
	if !anyDetector(out, "integrity:lockfile-vs-disk-name") {
		t.Fatalf("a swapped yarn alias directory must still fire, got: %+v", out)
	}
}

// TestLockDrift_YarnVersionDriftIsMedium — for yarn/pnpm we have no
// installed-bytes hash, so a disk version outside the pinned set is a
// staleness signal (node_modules out of sync with the lockfile), not a
// critical tamper alert. The identity-swap case is covered by name-drift.
func TestLockDrift_YarnVersionDriftIsMedium(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "yarn.lock"), `# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
`)
	mustWrite(t, filepath.Join(dir, "node_modules", "lodash", "package.json"), `{
	  "name": "lodash", "version": "4.17.20"
	}`)

	out, _ := New([]string{dir}).Detect(context.Background())
	f, ok := findingByDetector(out, "integrity:lockfile-vs-disk-version")
	if !ok {
		t.Fatalf("expected a version-drift finding, got: %+v", out)
	}
	if f.Severity != findings.SeverityMedium {
		t.Errorf("yarn version-drift should be medium (staleness), got %s", f.Severity)
	}
}

// TestLockDrift_NpmVersionDriftMirrorAgreesIsMedium — npm's own
// .package-lock.json reports the same version that's on disk, so the
// install is internally consistent and only the project lockfile is
// stale: medium, not critical.
func TestLockDrift_NpmVersionDriftMirrorAgreesIsMedium(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package-lock.json"), `{
	  "name": "test", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "test", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.21"}
	  }
	}`)
	mustWrite(t, filepath.Join(dir, "node_modules", ".package-lock.json"), `{
	  "lockfileVersion": 3,
	  "packages": {
	    "node_modules/lodash": {"version": "4.17.20"}
	  }
	}`)
	mustWrite(t, filepath.Join(dir, "node_modules", "lodash", "package.json"), `{
	  "name": "lodash", "version": "4.17.20"
	}`)

	out, _ := New([]string{dir}).Detect(context.Background())
	f, ok := findingByDetector(out, "integrity:lockfile-vs-disk-version")
	if !ok {
		t.Fatalf("expected a version-drift finding, got: %+v", out)
	}
	if f.Severity != findings.SeverityMedium {
		t.Errorf("mirror-agrees drift should be medium (staleness), got %s", f.Severity)
	}
}

// TestLockDrift_NpmVersionDriftNoMirrorIsCritical — without a
// .package-lock.json to confirm staleness, the on-disk bytes match
// neither the lockfile nor any record: keep it critical.
func TestLockDrift_NpmVersionDriftNoMirrorIsCritical(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package-lock.json"), `{
	  "name": "test", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "test", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.21"}
	  }
	}`)
	mustWrite(t, filepath.Join(dir, "node_modules", "lodash", "package.json"), `{
	  "name": "lodash", "version": "4.17.20"
	}`)

	out, _ := New([]string{dir}).Detect(context.Background())
	f, ok := findingByDetector(out, "integrity:lockfile-vs-disk-version")
	if !ok {
		t.Fatalf("expected a version-drift finding, got: %+v", out)
	}
	if f.Severity != findings.SeverityCritical {
		t.Errorf("unconfirmed drift should stay critical, got %s", f.Severity)
	}
}

func TestParsePnpmStoreDir(t *testing.T) {
	cases := []struct{ dir, name, version string }{
		{"lodash@4.17.21", "lodash", "4.17.21"},
		{"@babel+core@7.28.0", "@babel/core", "7.28.0"},
		{"react-dom@18.2.0_react@18.2.0", "react-dom", "18.2.0"},  // v6 peer suffix
		{"react-dom@18.2.0(react@18.2.0)", "react-dom", "18.2.0"}, // v7+ peer suffix
		{"@scope+pkg@1.0.0(peer@2.0.0)", "@scope/pkg", "1.0.0"},
		// Real-world cases the first cut got wrong (found by validating
		// the parser against ~2000 store dirs on disk):
		{"string_decoder@1.3.0", "string_decoder", "1.3.0"},                                // underscore in name
		{"@types+babel__core@7.20.5", "@types/babel__core", "7.20.5"},                      // DefinitelyTyped __ convention
		{"@angular-devkit+core@19.2.23_chokidar@4.0.3", "@angular-devkit/core", "19.2.23"}, // scoped name + peer suffix
		{"node_modules", "", ""}, // not a package dir
	}
	for _, c := range cases {
		n, v := parsePnpmStoreDir(c.dir)
		if n != c.name || v != c.version {
			t.Errorf("parsePnpmStoreDir(%q) = (%q,%q), want (%q,%q)", c.dir, n, v, c.name, c.version)
		}
	}
}

// TestLockDrift_PnpmDriftStaleIsMedium — pnpm's .pnpm store contains the
// on-disk version (4.17.20); the lockfile was bumped to 4.17.21 without a
// reinstall. The install is self-consistent → staleness, MEDIUM.
func TestLockDrift_PnpmDriftStaleIsMedium(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-AAA}
`)
	mustWrite(t, filepath.Join(dir, "node_modules", "lodash", "package.json"), `{"name":"lodash","version":"4.17.20"}`)
	// pnpm's own store recorded 4.17.20 — matches disk.
	mustWrite(t, filepath.Join(dir, "node_modules", ".pnpm", "lodash@4.17.20", "node_modules", "lodash", "package.json"), `{"name":"lodash","version":"4.17.20"}`)

	out, _ := New([]string{dir}).Detect(context.Background())
	f, ok := findingByDetector(out, "integrity:lockfile-vs-disk-version")
	if !ok {
		t.Fatalf("expected version-drift finding, got: %+v", out)
	}
	if f.Severity != findings.SeverityMedium {
		t.Errorf("store-confirmed stale drift should be medium, got %s", f.Severity)
	}
}

// TestLockDrift_PnpmDriftUnplacedIsCritical — the on-disk copy (4.17.20)
// matches no version in pnpm's store (which only has 4.17.21): pnpm never
// placed these bytes → possible tamper, CRITICAL.
func TestLockDrift_PnpmDriftUnplacedIsCritical(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-AAA}
`)
	mustWrite(t, filepath.Join(dir, "node_modules", "lodash", "package.json"), `{"name":"lodash","version":"4.17.20"}`)
	// Store only knows 4.17.21 — the on-disk 4.17.20 was never placed by pnpm.
	mustWrite(t, filepath.Join(dir, "node_modules", ".pnpm", "lodash@4.17.21", "node_modules", "lodash", "package.json"), `{"name":"lodash","version":"4.17.21"}`)

	out, _ := New([]string{dir}).Detect(context.Background())
	f, ok := findingByDetector(out, "integrity:lockfile-vs-disk-version")
	if !ok {
		t.Fatalf("expected version-drift finding, got: %+v", out)
	}
	if f.Severity != findings.SeverityCritical {
		t.Errorf("store-contradicted drift should be critical, got %s", f.Severity)
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
