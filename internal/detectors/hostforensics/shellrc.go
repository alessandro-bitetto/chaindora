package hostforensics

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

var shellRCFiles = []string{
	".bashrc",
	".bash_profile",
	".profile",
	".zshrc",
	".zshenv",
	".zprofile",
}

type shellPattern struct {
	Pattern *regexp.Regexp
	VulnID  string
	Summary string
}

var shellPatterns = []shellPattern{
	{
		Pattern: regexp.MustCompile(`curl[^|]+\|\s*(bash|sh|zsh)\b`),
		VulnID:  "HOST-SHELLRC-CURL-PIPE",
		Summary: "Shell rc file pipes curl output directly into a shell — classic post-compromise persistence.",
	},
	{
		Pattern: regexp.MustCompile(`wget[^|]+\|\s*(bash|sh|zsh)\b`),
		VulnID:  "HOST-SHELLRC-WGET-PIPE",
		Summary: "Shell rc file pipes wget output directly into a shell — classic post-compromise persistence.",
	},
	{
		Pattern: regexp.MustCompile(`eval\s+["']?\$\(\s*base64\s+(-d|--decode)`),
		VulnID:  "HOST-SHELLRC-EVAL-BASE64",
		Summary: "Shell rc file evals a base64-decoded payload — strong indicator of compromise.",
	},
	{
		Pattern: regexp.MustCompile(`eval\s+["']?\$\(\s*curl`),
		VulnID:  "HOST-SHELLRC-EVAL-CURL",
		Summary: "Shell rc file evals output of a network call — strong indicator of compromise.",
	},
	{
		Pattern: regexp.MustCompile(`\bnc\s+-l\b`),
		VulnID:  "HOST-SHELLRC-NETCAT-LISTENER",
		Summary: "Shell rc file launches a netcat listener — suspicious for an interactive shell config.",
	},
}

func scanShellRC(home string) []findings.Finding {
	var out []findings.Finding
	for _, name := range shellRCFiles {
		full := filepath.Join(home, name)
		f, err := os.Open(full)
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
			for _, p := range shellPatterns {
				if p.Pattern.MatchString(line) {
					out = append(out, findings.Finding{
						Detector:   "hostforensics:shellrc",
						VulnID:     p.VulnID,
						Summary:    fmt.Sprintf("%s (line %d: %q)", p.Summary, lineNo, truncate(trimmed, 120)),
						Severity:   findings.SeverityHigh,
						SourcePath: full,
					})
				}
			}
		}
		f.Close()
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
