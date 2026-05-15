package hostforensics

import (
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// ScanPersistence enumerates the OS's user-level persistence mechanisms
// (cron, launchd on macOS, systemd user units on Linux, Scheduled Tasks on
// Windows) and emits one LOW informational finding per entry plus a HIGH
// finding for any entry whose command matches the shellrc malware patterns
// (curl|bash, eval $(base64), eval $(curl), nc -l).
func ScanPersistence(home string) []findings.Finding {
	var out []findings.Finding
	switch runtime.GOOS {
	case "darwin":
		out = append(out, scanCron()...)
		out = append(out, scanLaunchAgents(home)...)
	case "linux":
		out = append(out, scanCron()...)
		out = append(out, scanSystemdUserUnits(home)...)
	case "windows":
		out = append(out, scanScheduledTasks()...)
	}
	return out
}

// ---- cron ----

func scanCron() []findings.Finding {
	if _, err := exec.LookPath("crontab"); err != nil {
		return nil
	}
	data, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		// No crontab installed for this user is a non-zero exit; treat as empty.
		return nil
	}
	return parseCrontabOutput(data, "crontab")
}

func parseCrontabOutput(data []byte, source string) []findings.Finding {
	var out []findings.Finding
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// crontab entries: 5 schedule fields (or @reboot/@hourly/etc.) + command
		fields := strings.Fields(line)
		var cmd string
		switch {
		case len(fields) >= 2 && strings.HasPrefix(fields[0], "@"):
			cmd = strings.Join(fields[1:], " ")
		case len(fields) >= 6:
			cmd = strings.Join(fields[5:], " ")
		default:
			continue
		}
		out = append(out, findings.Finding{
			Detector:   "hostforensics:persistence",
			VulnID:     "HOST-PERSISTENCE-CRON",
			Summary:    fmt.Sprintf("crontab entry (line %d): %s", i+1, truncate(cmd, 120)),
			Severity:   findings.SeverityLow,
			SourcePath: source,
		})
		out = append(out, checkSuspiciousCommand(cmd, source, "cron")...)
	}
	return out
}

// ---- launchd (macOS) ----

func scanLaunchAgents(home string) []findings.Finding {
	dirs := []string{filepath.Join(home, "Library", "LaunchAgents")}
	return scanPersistenceDir(dirs, ".plist", "HOST-PERSISTENCE-LAUNCHD", "launchd agent", "launchd")
}

// ---- systemd user units (Linux) ----

func scanSystemdUserUnits(home string) []findings.Finding {
	dirs := []string{filepath.Join(home, ".config", "systemd", "user")}
	return scanPersistenceDir(dirs, ".service", "HOST-PERSISTENCE-SYSTEMD-USER", "systemd user unit", "systemd")
}

// scanPersistenceDir is the shared file-enumeration helper for launchd and
// systemd-style persistence directories. Each matching file → one LOW
// informational finding, plus HIGH for any file whose contents trip a
// shellrc malware pattern.
func scanPersistenceDir(dirs []string, ext, vulnID, kindLabel, kindForSummary string) []findings.Finding {
	var out []findings.Finding
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ext) {
				continue
			}
			full := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(full)
			if err != nil {
				continue
			}
			out = append(out, findings.Finding{
				Detector:   "hostforensics:persistence",
				VulnID:     vulnID,
				Summary:    fmt.Sprintf("%s: %s", kindLabel, e.Name()),
				Severity:   findings.SeverityLow,
				SourcePath: full,
			})
			out = append(out, checkSuspiciousCommand(string(data), full, kindForSummary)...)
		}
	}
	return out
}

// ---- Windows Scheduled Tasks ----

func scanScheduledTasks() []findings.Finding {
	if _, err := exec.LookPath("schtasks"); err != nil {
		return nil
	}
	data, err := exec.Command("schtasks", "/Query", "/FO", "CSV", "/V").Output()
	if err != nil {
		return nil
	}
	return parseScheduledTasksCSV(data)
}

func parseScheduledTasksCSV(data []byte) []findings.Finding {
	r := csv.NewReader(strings.NewReader(string(data)))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return nil
	}
	header := rows[0]
	taskCol, cmdCol := -1, -1
	for i, h := range header {
		switch h {
		case "TaskName", "\"TaskName\"":
			taskCol = i
		case "Task To Run", "\"Task To Run\"":
			cmdCol = i
		}
	}
	if taskCol < 0 || cmdCol < 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []findings.Finding
	for _, row := range rows[1:] {
		if len(row) <= cmdCol {
			continue
		}
		name := strings.TrimSpace(row[taskCol])
		cmd := strings.TrimSpace(row[cmdCol])
		if name == "" || name == "TaskName" || cmd == "" || cmd == "N/A" {
			continue
		}
		key := name + "|" + cmd
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, findings.Finding{
			Detector:   "hostforensics:persistence",
			VulnID:     "HOST-PERSISTENCE-SCHEDTASK",
			Summary:    fmt.Sprintf("Scheduled Task %q runs: %s", name, truncate(cmd, 120)),
			Severity:   findings.SeverityLow,
			SourcePath: "schtasks",
		})
		out = append(out, checkSuspiciousCommand(cmd, "schtasks:"+name, "Scheduled Task")...)
	}
	return out
}

// ---- shared malicious-command check ----

// checkSuspiciousCommand runs the host-forensics shellrc patterns over the
// given command string and emits HIGH findings for each match. Used by every
// persistence sub-scanner so the detection logic stays in one place.
func checkSuspiciousCommand(cmd, source, kind string) []findings.Finding {
	var out []findings.Finding
	for _, p := range shellPatterns {
		if p.Pattern.MatchString(cmd) {
			out = append(out, findings.Finding{
				Detector:   "hostforensics:persistence",
				VulnID:     "HOST-PERSISTENCE-SUSPICIOUS",
				Summary:    fmt.Sprintf("%s (%s entry: %s)", p.Summary, kind, truncate(cmd, 100)),
				Severity:   findings.SeverityHigh,
				SourcePath: source,
			})
		}
	}
	return out
}
