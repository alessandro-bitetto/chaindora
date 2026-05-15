package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

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

// writeText renders findings as human-readable output: severity-sorted,
// grouped into sections, with word-wrapped summaries and trimmed reference
// lists. Designed for skim-ability — for full data use --format json.
const (
	maxRefsShown = 2
	wrapWidth    = 76
)

// ANSI color helpers. Emitted only when the writer is a TTY and NO_COLOR is
// unset (https://no-color.org/). Empty strings otherwise — the formatting
// stays correct in pipes / files / CI logs without ANSI noise.
type palette struct {
	reset, bold, red, magenta, yellow, blue, gray, cyan string
}

func newPalette(w io.Writer) palette {
	if !isTerm(w) {
		return palette{}
	}
	return palette{
		reset:   "\x1b[0m",
		bold:    "\x1b[1m",
		red:     "\x1b[31m",
		magenta: "\x1b[35m",
		yellow:  "\x1b[33m",
		blue:    "\x1b[34m",
		gray:    "\x1b[90m",
		cyan:    "\x1b[36m",
	}
}

func isTerm(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func writeText(w io.Writer, fs []findings.Finding) {
	if len(fs) == 0 {
		fmt.Fprintln(w, "no known supply chain compromises detected")
		return
	}

	p := newPalette(w)
	groups := groupAndSort(fs)

	// Top-line summary: total + per-severity counts.
	parts := make([]string, 0, len(groups.order))
	for _, sev := range groups.order {
		count := len(groups.bySev[sev])
		if count == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d %s", count, strings.ToLower(string(sev))))
	}
	fmt.Fprintf(w, "%s%d findings%s — %s\n\n", p.bold, len(fs), p.reset, strings.Join(parts, ", "))

	// Per-severity sections in priority order.
	idx := 0
	for _, sev := range groups.order {
		group := groups.bySev[sev]
		if len(group) == 0 {
			continue
		}
		writeSection(w, p, sev, group, &idx)
	}
}

type grouped struct {
	bySev map[findings.Severity][]findings.Finding
	order []findings.Severity
}

func groupAndSort(fs []findings.Finding) grouped {
	g := grouped{
		bySev: make(map[findings.Severity][]findings.Finding),
		order: []findings.Severity{
			findings.SeverityCritical,
			findings.SeverityHigh,
			findings.SeverityMedium,
			findings.SeverityLow,
			findings.SeverityUnknown,
		},
	}
	for _, f := range fs {
		key := f.Severity
		if key == "" {
			key = findings.SeverityUnknown
		}
		g.bySev[key] = append(g.bySev[key], f)
	}
	// Within each severity, stable order: detector, then vuln-id, then name.
	for sev := range g.bySev {
		sort.SliceStable(g.bySev[sev], func(i, j int) bool {
			a, b := g.bySev[sev][i], g.bySev[sev][j]
			if a.Detector != b.Detector {
				return a.Detector < b.Detector
			}
			if a.VulnID != b.VulnID {
				return a.VulnID < b.VulnID
			}
			return a.Name < b.Name
		})
	}
	return g
}

func writeSection(w io.Writer, p palette, sev findings.Severity, fs []findings.Finding, idx *int) {
	bar := strings.Repeat("=", wrapWidth+4)
	sevColor := severityColor(p, sev)
	fmt.Fprintln(w, bar)
	fmt.Fprintf(w, "%s%s%s  (%d %s)\n", sevColor, strings.ToUpper(string(sev)), p.reset,
		len(fs), pluralize("finding", len(fs)))
	fmt.Fprintln(w, bar)
	fmt.Fprintln(w)
	for _, f := range fs {
		*idx++
		writeFinding(w, p, *idx, f)
	}
}

func writeFinding(w io.Writer, p palette, num int, f findings.Finding) {
	// Headline: #N  detector | vuln-id | purl-or-name
	loc := f.PURL
	if loc == "" {
		loc = f.Name
	}
	parts := []string{f.Detector}
	if f.VulnID != "" {
		parts = append(parts, f.VulnID)
	}
	if loc != "" {
		parts = append(parts, loc)
	}
	fmt.Fprintf(w, "  %s#%d%s  %s%s%s\n", p.bold, num, p.reset, p.cyan, strings.Join(parts, " | "), p.reset)

	// Summary, word-wrapped under a hanging indent.
	if s := strings.TrimSpace(f.Summary); s != "" {
		for _, line := range wrapWords(s, wrapWidth) {
			fmt.Fprintf(w, "      %s\n", line)
		}
	}

	// SourcePath, when distinct from the headline (file artifacts) or worth
	// surfacing (project lockfile / global-pkg source).
	if f.SourcePath != "" && f.SourcePath != loc {
		fmt.Fprintf(w, "      %ssource:%s %s\n", p.gray, p.reset, f.SourcePath)
	}

	// Fix hint, if the detector knows a clean version to pin to.
	if f.FixUpgradeTo != "" {
		fmt.Fprintf(w, "      %sfix:%s    upgrade to %s%s%s\n", p.gray, p.reset, p.bold, f.FixUpgradeTo, p.reset)
	}

	// References — top N, with a tail count for the rest.
	if len(f.References) > 0 {
		shown := f.References
		hidden := 0
		if len(shown) > maxRefsShown {
			hidden = len(shown) - maxRefsShown
			shown = shown[:maxRefsShown]
		}
		fmt.Fprintf(w, "      %srefs:%s   %s\n", p.gray, p.reset, shown[0])
		for _, ref := range shown[1:] {
			fmt.Fprintf(w, "              %s\n", ref)
		}
		if hidden > 0 {
			fmt.Fprintf(w, "              %s(+%d more — use --format json for the full list)%s\n", p.gray, hidden, p.reset)
		}
	}

	fmt.Fprintln(w)
}

func severityColor(p palette, sev findings.Severity) string {
	if p.reset == "" {
		return ""
	}
	switch sev {
	case findings.SeverityCritical:
		return p.bold + p.red
	case findings.SeverityHigh:
		return p.bold + p.magenta
	case findings.SeverityMedium:
		return p.yellow
	case findings.SeverityLow:
		return p.blue
	}
	return p.gray
}

// wrapWords greedy-wraps s onto lines of at most width characters. Single
// words longer than width are emitted on their own line uncut (URLs etc).
func wrapWords(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	current := words[0]
	for _, word := range words[1:] {
		if len(current)+1+len(word) > width {
			lines = append(lines, current)
			current = word
		} else {
			current += " " + word
		}
	}
	lines = append(lines, current)
	return lines
}

func pluralize(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
