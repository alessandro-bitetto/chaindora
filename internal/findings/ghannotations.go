package findings

import (
	"fmt"
	"io"
	"strings"
)

// EmitGitHubAnnotations prints findings as GitHub Actions workflow commands
// (https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions).
// When emitted to stdout from inside a GitHub Actions run, each line creates
// an inline annotation on the pull-request diff or workflow summary.
func EmitGitHubAnnotations(w io.Writer, fs []Finding) error {
	for _, f := range fs {
		level := annotationLevel(f.Severity)
		msg := fmt.Sprintf("[%s] %s — %s (%s)", f.VulnID, f.Summary, f.Name, f.Detector)
		msg = escapeAnnotation(msg)
		if f.SourcePath != "" {
			fmt.Fprintf(w, "::%s file=%s,line=1::%s\n", level, escapeAnnotation(f.SourcePath), msg)
		} else {
			fmt.Fprintf(w, "::%s::%s\n", level, msg)
		}
	}
	return nil
}

func annotationLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	}
	return "notice"
}

// escapeAnnotation applies the percent-encoding required for embedded newlines
// and commas in GitHub workflow command values.
func escapeAnnotation(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}
