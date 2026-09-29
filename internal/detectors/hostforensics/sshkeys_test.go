package hostforensics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHFirstRunCreatesBaseline(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(sshDir, 0o700)
	keys := `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfake1== alice@laptop
# comment line
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfake2 bob@desktop
`
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(keys), 0o600); err != nil {
		t.Fatal(err)
	}

	got := ScanSSHAuthorizedKeys(home, "")
	if len(got) != 1 || got[0].VulnID != "HOST-SSH-BASELINE-CREATED" {
		t.Fatalf("expected single baseline-created finding, got %+v", got)
	}
	if _, err := os.Stat(SSHBaselinePath(home)); err != nil {
		t.Errorf("baseline file not written: %v", err)
	}
}

func TestSSHDiffDetectsAddedKey(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(sshDir, 0o700)

	original := "ssh-rsa AAAAfake1 alice@laptop\n"
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	// First run: create baseline
	if got := ScanSSHAuthorizedKeys(home, ""); len(got) != 1 {
		t.Fatalf("baseline run: %+v", got)
	}

	// Add a key
	withAdded := original + "ssh-ed25519 AAAAfake-attacker mallory@evil\n"
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(withAdded), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ScanSSHAuthorizedKeys(home, "")
	if len(got) != 1 {
		t.Fatalf("expected 1 added-key finding, got %d: %+v", len(got), got)
	}
	if got[0].VulnID != "HOST-SSH-KEY-ADDED" {
		t.Errorf("wrong VulnID: %+v", got[0])
	}
}

func TestSSHDiffDetectsRemovedKey(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(sshDir, 0o700)

	original := "ssh-rsa AAAAfake1 alice@laptop\nssh-ed25519 AAAAfake2 bob@desktop\n"
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = ScanSSHAuthorizedKeys(home, "")

	// Remove one
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte("ssh-rsa AAAAfake1 alice@laptop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ScanSSHAuthorizedKeys(home, "")
	if len(got) != 1 || got[0].VulnID != "HOST-SSH-KEY-REMOVED" {
		t.Fatalf("expected 1 removed-key finding, got %+v", got)
	}
}

func TestSSHNoAuthorizedKeys(t *testing.T) {
	home := t.TempDir()
	if got := ScanSSHAuthorizedKeys(home, ""); len(got) != 0 {
		t.Errorf("expected 0 findings when authorized_keys missing, got %d: %+v", len(got), got)
	}
}

func TestSSHIgnoresCommentsAndBlanks(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(sshDir, 0o700)
	keys := `# top-level comment
ssh-rsa AAAAfake1 alice

ssh-ed25519 AAAAfake2 bob
# another
`
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(keys), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ScanSSHAuthorizedKeys(home, "")
	if len(got) != 1 || !strings.Contains(got[0].Summary, "Baseline of 2") {
		t.Errorf("expected baseline with 2 keys, got %+v", got)
	}
}
