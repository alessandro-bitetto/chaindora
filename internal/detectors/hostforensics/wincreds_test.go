package hostforensics

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanCredentialDirsEmpty(t *testing.T) {
	tmp := t.TempDir()
	if got := scanCredentialDirs([]string{tmp}); len(got) != 0 {
		t.Errorf("empty dir → 0 findings, got %d", len(got))
	}
	if got := scanCredentialDirs([]string{filepath.Join(tmp, "nonexistent")}); len(got) != 0 {
		t.Errorf("missing dir → 0 findings, got %d", len(got))
	}
}

func TestScanCredentialDirsNonEmpty(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "blob1.dat"), []byte("opaque"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "blob2.dat"), []byte("opaque"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := scanCredentialDirs([]string{tmp})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding for non-empty cred dir, got %d", len(got))
	}
	if got[0].VulnID != "HOST-WINDOWS-CREDS-PRESENT" {
		t.Errorf("wrong VulnID: %+v", got[0])
	}
}
