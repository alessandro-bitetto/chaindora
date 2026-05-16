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
