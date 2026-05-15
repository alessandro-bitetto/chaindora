package hostforensics

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// powershellProfilePaths returns the typical PowerShell profile file
// locations relative to home. Covers cross-platform pwsh (PowerShell Core /
// 7+) on macOS and Linux, plus both PS Core and legacy Windows PowerShell
// on Windows.
func powershellProfilePaths(home string) []string {
	paths := []string{
		filepath.Join(home, ".config", "powershell", "Microsoft.PowerShell_profile.ps1"),
		filepath.Join(home, ".config", "powershell", "profile.ps1"),
	}
	if runtime.GOOS == "windows" {
		paths = append(paths,
			filepath.Join(home, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
			filepath.Join(home, "Documents", "PowerShell", "profile.ps1"),
			filepath.Join(home, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
			filepath.Join(home, "Documents", "WindowsPowerShell", "profile.ps1"),
		)
	}
	return paths
}

type powershellPattern struct {
	Pattern *regexp.Regexp
	VulnID  string
	Summary string
}

var powershellPatterns = []powershellPattern{
	{
		// iex (irm https://...) — the classic PowerShell-malware loader.
		Pattern: regexp.MustCompile(`(?i)\b(iex|invoke-expression)\b\s*\(?\s*(irm|invoke-restmethod|iwr|invoke-webrequest)\b`),
		VulnID:  "HOST-POWERSHELL-IEX-WEB",
		Summary: "PowerShell profile invokes-expression on output of a web request — classic malware loader pattern",
	},
	{
		Pattern: regexp.MustCompile(`(?i)\[Convert\]::FromBase64String`),
		VulnID:  "HOST-POWERSHELL-BASE64",
		Summary: "PowerShell profile decodes a base64 payload — strong indicator of obfuscation",
	},
	{
		Pattern: regexp.MustCompile(`(?i)Add-MpPreference\s+-Exclusion`),
		VulnID:  "HOST-POWERSHELL-AV-EXCLUSION",
		Summary: "PowerShell profile adds a Windows Defender exclusion — common AV-bypass technique",
	},
	{
		Pattern: regexp.MustCompile(`(?i)Set-MpPreference.*DisableRealtimeMonitoring\s*\$?true`),
		VulnID:  "HOST-POWERSHELL-AV-DISABLE",
		Summary: "PowerShell profile disables Windows Defender real-time monitoring",
	},
}

// scanPowerShell walks each candidate PowerShell profile path and applies
// the malware-loader regexes line by line, skipping `#` comments.
func scanPowerShell(home string) []findings.Finding {
	var out []findings.Finding
	for _, path := range powershellProfilePaths(home) {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			line := sc.Text()
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			for _, p := range powershellPatterns {
				if p.Pattern.MatchString(line) {
					out = append(out, findings.Finding{
						Detector:   "hostforensics:powershell",
						VulnID:     p.VulnID,
						Summary:    fmt.Sprintf("%s (line %d: %q)", p.Summary, lineNo, truncate(trimmed, 120)),
						Severity:   findings.SeverityHigh,
						SourcePath: path,
					})
				}
			}
		}
		_ = f.Close()
	}
	return out
}
