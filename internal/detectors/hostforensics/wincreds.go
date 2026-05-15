package hostforensics

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// scanWindowsCredentials reports the presence of Windows Credential Manager
// blobs. The OS encrypts the contents — chaindora does NOT attempt to
// decrypt — but a non-empty Credentials directory means an attacker with
// code execution on this account could enumerate / use them.
func scanWindowsCredentials(home string) []findings.Finding {
	if runtime.GOOS != "windows" {
		return nil
	}
	return scanCredentialDirs([]string{
		filepath.Join(home, "AppData", "Local", "Microsoft", "Credentials"),
		filepath.Join(home, "AppData", "Roaming", "Microsoft", "Credentials"),
	})
}

// scanCredentialDirs is extracted for testability — the runtime.GOOS gate
// in scanWindowsCredentials makes the wrapper untestable on non-Windows hosts.
func scanCredentialDirs(dirs []string) []findings.Finding {
	var out []findings.Finding
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) == 0 {
			continue
		}
		out = append(out, findings.Finding{
			Detector: "hostforensics:tokens",
			VulnID:   "HOST-WINDOWS-CREDS-PRESENT",
			Summary: fmt.Sprintf(
				"Windows Credential Manager contains %d stored credential blob(s) in %s. If a recent supply-chain compromise had code execution on this account, rotate stored credentials.",
				len(entries), dir,
			),
			Severity:   findings.SeverityMedium,
			SourcePath: dir,
		})
	}
	return out
}
