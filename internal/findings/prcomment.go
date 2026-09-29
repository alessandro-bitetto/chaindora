package findings

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// EmitPRComment writes a GitHub-flavored markdown body suitable
// for `gh pr comment` or actions/github-script sticky-comment
// flows. Designed to read well at any size — collapsible
// `<details>` blocks keep the comment compact when there are
// many findings.
//
// The "marker" line at the top (`<!-- chaindora:pr-comment -->`)
// lets a sticky-comment action find the previous comment and
// update it in place instead of stacking duplicates.
func EmitPRComment(w io.Writer, current []Finding, suppressed []SuppressedFinding, newSinceBaseline []Finding, removedFingerprints []string, chdoraVersion string) error {
	fmt.Fprintln(w, "<!-- chaindora:pr-comment -->")
	fmt.Fprintln(w, "## chaindora supply-chain scan")
	fmt.Fprintln(w)

	// One-line verdict at the top — that's what reviewers see
	// without expanding anything.
	verdict := summaryVerdict(current, newSinceBaseline)
	fmt.Fprintln(w, verdict)
	fmt.Fprintln(w)

	// Summary counts table.
	counts := countBySeverity(current)
	fmt.Fprintln(w, "| Severity | Total | New since baseline |")
	fmt.Fprintln(w, "|---|---:|---:|")
	newBySev := countBySeverity(newSinceBaseline)
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityUnknown} {
		if counts[sev] == 0 && newBySev[sev] == 0 {
			continue
		}
		fmt.Fprintf(w, "| %s | %d | %d |\n", sev, counts[sev], newBySev[sev])
	}
	fmt.Fprintln(w)

	// New-this-PR findings — most important section, expanded
	// by default.
	if len(newSinceBaseline) > 0 {
		fmt.Fprintf(w, "### %d new finding(s) since baseline\n\n", len(newSinceBaseline))
		renderFindingsTable(w, newSinceBaseline)
		fmt.Fprintln(w)
	}

	// Pre-existing findings — collapsed so reviewers can ignore
	// them by default. Only shown if there ARE pre-existing
	// (current minus new = pre-existing) so the "clean repo"
	// case doesn't render an empty <details>.
	preExisting := len(current) - len(newSinceBaseline)
	if preExisting > 0 {
		fmt.Fprintf(w, "<details><summary>%d pre-existing finding(s)</summary>\n\n", preExisting)
		// Build the pre-existing slice by excluding new ones.
		newSet := make(map[string]struct{}, len(newSinceBaseline))
		for _, f := range newSinceBaseline {
			newSet[Fingerprint(f)] = struct{}{}
		}
		pre := make([]Finding, 0, preExisting)
		for _, f := range current {
			if _, isNew := newSet[Fingerprint(f)]; !isNew {
				pre = append(pre, f)
			}
		}
		renderFindingsTable(w, pre)
		fmt.Fprintln(w, "\n</details>")
		fmt.Fprintln(w)
	}

	// Suppressed findings — surfaced under a collapsible block
	// so the audit trail is visible on PR without cluttering.
	// Expired suppressions break out into their own warning.
	if len(suppressed) > 0 {
		expired := 0
		for _, s := range suppressed {
			if s.Expired {
				expired++
			}
		}
		if expired > 0 {
			fmt.Fprintf(w, "> ⚠ **%d expired suppression(s)** — review and refresh\n\n", expired)
		}
		fmt.Fprintf(w, "<details><summary>%d suppressed finding(s)</summary>\n\n", len(suppressed))
		fmt.Fprintln(w, "| Severity | Package | VulnID | Reason | Expired |")
		fmt.Fprintln(w, "|---|---|---|---|:---:|")
		for _, s := range suppressed {
			expFlag := ""
			if s.Expired {
				expFlag = "yes"
			}
			fmt.Fprintf(w, "| %s | `%s@%s` | `%s` | %s | %s |\n",
				s.Finding.Severity,
				s.Finding.Name, s.Finding.Version,
				s.Finding.VulnID,
				escapeMD(s.Suppression.Reason),
				expFlag)
		}
		fmt.Fprintln(w, "\n</details>")
		fmt.Fprintln(w)
	}

	// Resolved-since-baseline note.
	if len(removedFingerprints) > 0 {
		fmt.Fprintf(w, "> %d finding(s) resolved since the baseline. Consider running `chdora ci --update-baseline` to refresh.\n\n",
			len(removedFingerprints))
	}

	fmt.Fprintf(w, "<sub>chaindora %s · [docs](https://chaindora.dev) · [report a false positive](https://github.com/alessandro-bitetto/chaindora/issues/new)</sub>\n", chdoraVersion)
	return nil
}

// summaryVerdict produces the one-line top-of-comment verdict.
// Mirrors the SonarQube quality-gate ux: pass / warn / fail.
func summaryVerdict(current, newSinceBaseline []Finding) string {
	if len(current) == 0 {
		return "**✅ No findings.**"
	}
	if len(newSinceBaseline) == 0 {
		return fmt.Sprintf("**🟡 %d pre-existing finding(s); none new on this PR.**", len(current))
	}
	newCount := len(newSinceBaseline)
	criticalNew := 0
	highNew := 0
	for _, f := range newSinceBaseline {
		switch f.Severity {
		case SeverityCritical:
			criticalNew++
		case SeverityHigh:
			highNew++
		}
	}
	if criticalNew > 0 {
		return fmt.Sprintf("**🔴 %d new finding(s) introduced — %d critical, %d high.** Block on critical/high.", newCount, criticalNew, highNew)
	}
	if highNew > 0 {
		return fmt.Sprintf("**🟠 %d new finding(s) introduced — %d high.** Review before merge.", newCount, highNew)
	}
	return fmt.Sprintf("**🟡 %d new finding(s) introduced** (all medium/low/unknown).", newCount)
}

func renderFindingsTable(w io.Writer, fs []Finding) {
	if len(fs) == 0 {
		fmt.Fprintln(w, "_(none)_")
		return
	}
	// Sort: severity high→low, then package name.
	sorted := append([]Finding(nil), fs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if severityWeight(sorted[i].Severity) != severityWeight(sorted[j].Severity) {
			return severityWeight(sorted[i].Severity) > severityWeight(sorted[j].Severity)
		}
		return sorted[i].Name < sorted[j].Name
	})
	fmt.Fprintln(w, "| Severity | Package | VulnID | Source |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, f := range sorted {
		fmt.Fprintf(w, "| %s | `%s@%s` | `%s` | `%s` |\n",
			f.Severity,
			f.Name, f.Version,
			f.VulnID,
			escapeMD(f.SourcePath))
	}
}

func countBySeverity(fs []Finding) map[Severity]int {
	out := map[Severity]int{}
	for _, f := range fs {
		out[f.Severity]++
	}
	return out
}

func severityWeight(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// escapeMD blunts pipe / backtick / underscore that would
// otherwise break tables. Conservative — the goal is readable
// PR comments, not roundtrip fidelity.
func escapeMD(s string) string {
	if s == "" {
		return ""
	}
	r := strings.NewReplacer(
		"|", `\|`,
		"`", "'",
		"\n", " ",
	)
	return r.Replace(s)
}
