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
// grouped into sections, deduplicated by (VulnID, PURL) so the same CVE
// across multiple projects shows once with all source paths listed,
// word-wrapped summaries, and trimmed reference lists. Designed for
// skim-ability — for the full ungrouped data use --format json.
const (
	maxRefsShown    = 2
	maxSourcesShown = 4
	wrapWidth       = 76
)

// renderGroup is a render-time aggregation: one row per unique
// (VulnID, PURL) pair across the input Finding slice. Sources accumulates
// every distinct SourcePath that produced a finding in the group.
type renderGroup struct {
	findings.Finding
	Sources []string
}

// groupForRender collapses a flat Finding slice into per-(VulnID, PURL)
// groups while preserving severity grouping downstream (groups inherit
// the headline finding's severity). When VulnID and PURL are both empty
// (rare — only happens for malformed findings), the group key falls back
// to the SourcePath so each unique artifact still gets its own entry.
func groupForRender(fs []findings.Finding) []renderGroup {
	type key struct{ vulnID, purl, fallback string }
	groups := map[key]*renderGroup{}
	var order []key
	for _, f := range fs {
		k := key{vulnID: f.VulnID, purl: f.PURL}
		if k.vulnID == "" && k.purl == "" {
			k.fallback = f.SourcePath
		}
		g, ok := groups[k]
		if !ok {
			g = &renderGroup{Finding: f}
			groups[k] = g
			order = append(order, k)
		}
		if f.SourcePath != "" {
			g.Sources = append(g.Sources, f.SourcePath)
		}
	}
	out := make([]renderGroup, 0, len(order))
	for _, k := range order {
		g := groups[k]
		// Deduplicate + sort the source paths so output is stable
		// across runs.
		seen := map[string]struct{}{}
		uniq := g.Sources[:0]
		for _, s := range g.Sources {
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			uniq = append(uniq, s)
		}
		sort.Strings(uniq)
		g.Sources = uniq
		out = append(out, *g)
	}
	return out
}

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

// cveSectionPreviewSize controls how many dependency-CVE findings show
// in the default text output. The rest collapse into a "+N more — use
// --show-all-cves" line. The supply-chain section is always shown in
// full because that's chdora's primary identity.
const cveSectionPreviewSize = 5

// ShowAllCVEs, when true, disables the collapse of the
// dependency-CVE section. Set from the CLI's --show-all-cves flag.
var ShowAllCVEs bool

// SupplyChainOnly, when true, hides the dependency-CVE section
// entirely. Set from the CLI's --supply-chain-only flag.
var SupplyChainOnly bool

func writeText(w io.Writer, fs []findings.Finding) {
	if len(fs) == 0 {
		fmt.Fprintln(w, "no known supply chain compromises detected")
		return
	}

	p := newPalette(w)
	rgs := groupForRender(fs)

	// Partition by category. The supply-chain section comes first
	// and gets the loud presentation; the dep-CVE section is
	// collapsed by default. host-forensics + configuration findings
	// fold into the supply-chain block because they're chdora-
	// specific signals that don't appear in commodity SCA tools.
	supplyChain, depCVE := partitionByCategory(rgs)

	// Top-line summary unchanged.
	totalUnique := len(rgs)
	totalInstances := len(fs)
	sevParts := summaryBySeverity(rgs)
	summary := fmt.Sprintf("%s%d findings%s — %s", p.bold, totalUnique, p.reset, strings.Join(sevParts, ", "))
	if totalInstances > totalUnique {
		summary += fmt.Sprintf(" %s(deduplicated from %d instances)%s", p.gray, totalInstances, p.reset)
	}
	fmt.Fprintln(w, summary)
	fmt.Fprintln(w)

	idx := 0

	// === SUPPLY-CHAIN ATTACK SIGNALS section ===
	if len(supplyChain) > 0 {
		writeBanner(w, p, "SUPPLY-CHAIN ATTACK SIGNALS", supplyChain, p.bold+p.red)
		// Within the section, sort by severity.
		grouped := groupAndSort(supplyChain)
		for _, sev := range grouped.order {
			group := grouped.bySev[sev]
			if len(group) == 0 {
				continue
			}
			writeSection(w, p, sev, group, &idx)
		}
	}

	// === DEPENDENCY VULNERABILITIES section ===
	if !SupplyChainOnly && len(depCVE) > 0 {
		writeBanner(w, p, "DEPENDENCY VULNERABILITIES (OSV.dev)", depCVE, p.bold+p.cyan)
		grouped := groupAndSort(depCVE)
		shown := 0
		for _, sev := range grouped.order {
			group := grouped.bySev[sev]
			if len(group) == 0 {
				continue
			}
			if !ShowAllCVEs {
				// Collapse: show only up to cveSectionPreviewSize
				// findings total across all severities, then bail.
				remaining := cveSectionPreviewSize - shown
				if remaining <= 0 {
					break
				}
				if len(group) > remaining {
					group = group[:remaining]
				}
			}
			writeSection(w, p, sev, group, &idx)
			shown += len(group)
		}
		if !ShowAllCVEs && shown < len(depCVE) {
			fmt.Fprintf(w, "  %s... and %d more dependency CVE finding(s) — re-run with --show-all-cves%s\n",
				p.gray, len(depCVE)-shown, p.reset)
			fmt.Fprintln(w)
		}
	}
}

func partitionByCategory(rgs []renderGroup) (supplyChain, depCVE []renderGroup) {
	for _, g := range rgs {
		cat := findings.DeriveCategory(g.Finding)
		if cat == findings.CategoryDependencyCVE {
			depCVE = append(depCVE, g)
		} else {
			// Supply-chain + host-forensics + configuration + unknown
			// all land here. chdora's identity findings.
			supplyChain = append(supplyChain, g)
		}
	}
	return supplyChain, depCVE
}

func summaryBySeverity(rgs []renderGroup) []string {
	order := []findings.Severity{
		findings.SeverityCritical, findings.SeverityHigh,
		findings.SeverityMedium, findings.SeverityLow,
		findings.SeverityUnknown,
	}
	counts := map[findings.Severity]int{}
	for _, g := range rgs {
		s := g.Severity
		if s == "" {
			s = findings.SeverityUnknown
		}
		counts[s]++
	}
	var parts []string
	for _, sev := range order {
		if c := counts[sev]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, strings.ToLower(string(sev))))
		}
	}
	return parts
}

func writeBanner(w io.Writer, p palette, title string, group []renderGroup, color string) {
	bar := strings.Repeat("=", wrapWidth+4)
	sevParts := summaryBySeverity(group)
	fmt.Fprintln(w, bar)
	fmt.Fprintf(w, "%s%s%s  (%d finding%s — %s)\n",
		color, title, p.reset,
		len(group), pluralSuffix(len(group)), strings.Join(sevParts, ", "))
	fmt.Fprintln(w, bar)
	fmt.Fprintln(w)
}

type grouped struct {
	bySev map[findings.Severity][]renderGroup
	order []findings.Severity
}

func groupAndSort(rgs []renderGroup) grouped {
	g := grouped{
		bySev: make(map[findings.Severity][]renderGroup),
		order: []findings.Severity{
			findings.SeverityCritical,
			findings.SeverityHigh,
			findings.SeverityMedium,
			findings.SeverityLow,
			findings.SeverityUnknown,
		},
	}
	for _, rg := range rgs {
		key := rg.Severity
		if key == "" {
			key = findings.SeverityUnknown
		}
		g.bySev[key] = append(g.bySev[key], rg)
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

func writeSection(w io.Writer, p palette, sev findings.Severity, rgs []renderGroup, idx *int) {
	bar := strings.Repeat("=", wrapWidth+4)
	sevColor := severityColor(p, sev)
	fmt.Fprintln(w, bar)
	fmt.Fprintf(w, "%s%s%s  (%d %s)\n", sevColor, strings.ToUpper(string(sev)), p.reset,
		len(rgs), pluralize("finding", len(rgs)))
	fmt.Fprintln(w, bar)
	fmt.Fprintln(w)
	for _, rg := range rgs {
		*idx++
		writeFinding(w, p, *idx, rg)
	}
}

func writeFinding(w io.Writer, p palette, num int, g renderGroup) {
	f := g.Finding
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

	// Sources — list every distinct path the group collapsed across.
	// Singular line for 1 source (matches the pre-grouping layout);
	// plural block for 2+, truncated past maxSourcesShown.
	sources := g.Sources
	switch len(sources) {
	case 0:
		// No sources beyond what's encoded in the headline (e.g. global
		// packages where PURL fully identifies the install).
	case 1:
		if sources[0] != loc {
			fmt.Fprintf(w, "      %ssource:%s  %s\n", p.gray, p.reset, sources[0])
		}
	default:
		fmt.Fprintf(w, "      %ssources:%s %s\n", p.gray, p.reset, sources[0])
		shown := sources[1:]
		hidden := 0
		if len(shown) > maxSourcesShown-1 {
			hidden = len(shown) - (maxSourcesShown - 1)
			shown = shown[:maxSourcesShown-1]
		}
		for _, s := range shown {
			fmt.Fprintf(w, "               %s\n", s)
		}
		if hidden > 0 {
			fmt.Fprintf(w, "               %s(+%d more occurrence%s — use --format json for the full list)%s\n",
				p.gray, hidden, pluralSuffix(hidden), p.reset)
		}
	}

	// Fix hint, if the detector knows a clean version to pin to.
	if f.FixUpgradeTo != "" {
		fmt.Fprintf(w, "      %sfix:%s     upgrade to %s%s%s\n", p.gray, p.reset, p.bold, f.FixUpgradeTo, p.reset)
	}

	// References — top N, with a tail count for the rest.
	if len(f.References) > 0 {
		shown := f.References
		hidden := 0
		if len(shown) > maxRefsShown {
			hidden = len(shown) - maxRefsShown
			shown = shown[:maxRefsShown]
		}
		fmt.Fprintf(w, "      %srefs:%s    %s\n", p.gray, p.reset, shown[0])
		for _, ref := range shown[1:] {
			fmt.Fprintf(w, "               %s\n", ref)
		}
		if hidden > 0 {
			fmt.Fprintf(w, "               %s(+%d more — use --format json for the full list)%s\n", p.gray, hidden, p.reset)
		}
	}

	fmt.Fprintln(w)
}

func pluralSuffix(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
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
