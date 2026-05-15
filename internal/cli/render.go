package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// renderFindings writes findings in the requested format. format must be one
// of: text, json, jsonl, sarif, github.
func renderFindings(w io.Writer, fs []findings.Finding, format string) error {
	switch format {
	case "", "text":
		writeText(w, fs)
		return nil
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(fs)
	case "jsonl":
		return findings.EmitJSONL(w, fs)
	case "sarif":
		return findings.EmitSARIF(w, fs, Version)
	case "github":
		return findings.EmitGitHubAnnotations(w, fs)
	}
	return fmt.Errorf("unknown format %q (want text|json|jsonl|sarif|github)", format)
}

// effectiveFormat applies the deprecated --json shortcut on top of --format.
// --json wins only if --format is at its default ("text").
func effectiveFormat(format string, jsonShortcut bool) string {
	if jsonShortcut && (format == "" || format == "text") {
		return "json"
	}
	return format
}

func writeText(w io.Writer, fs []findings.Finding) {
	if len(fs) == 0 {
		fmt.Fprintln(w, "no known supply chain compromises detected")
		return
	}
	fmt.Fprintf(w, "%d finding(s):\n\n", len(fs))
	for _, f := range fs {
		head := f.PURL
		if head == "" {
			head = f.SourcePath
		}
		fmt.Fprintf(w, "  [%s] [%s] %s\n", f.Severity, f.Detector, head)
		fmt.Fprintf(w, "    %s — %s\n", f.VulnID, f.Summary)
		if f.SourcePath != "" && f.SourcePath != head {
			fmt.Fprintf(w, "    source: %s\n", f.SourcePath)
		}
		for _, ref := range f.References {
			fmt.Fprintf(w, "    ref: %s\n", ref)
		}
		fmt.Fprintln(w)
	}
}
