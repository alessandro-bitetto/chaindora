package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// detectorTally accumulates per-detector finding counts across a single
// command invocation so we can print one clean summary table at the end
// — instead of the v0.5.x pattern where each detector printed its own
// "X findings: N" line inline, which looked like "0 findings overall"
// to anyone reading the first stderr line.
//
// Each detector class registers itself once (via Enable) so it still
// shows up with a 0 count even when it found nothing — that's a useful
// signal too ("0 leaked credentials" is reassuring, not silence).
// Findings are absorbed in bulk via AbsorbFindings, which folds
// sub-detector classes (heuristic:dep-confusion, hostforensics:tokens)
// into their family root.
type detectorTally struct {
	order  []string
	counts map[string]int
}

func newDetectorTally() *detectorTally {
	return &detectorTally{counts: map[string]int{}}
}

// Enable registers that a detector class ran during this invocation,
// even if it produced no findings. Subsequent AbsorbFindings calls may
// raise the count above zero. Idempotent.
func (t *detectorTally) Enable(class string) {
	if _, ok := t.counts[class]; !ok {
		t.counts[class] = 0
		t.order = append(t.order, class)
	}
}

// AbsorbFindings folds every f.Detector into the tally, mapping
// sub-detector tags (`heuristic:dep-confusion`, `hostforensics:tokens`)
// to their family root. Detectors that produce findings but weren't
// Enable'd in advance are appended at the end of the table.
func (t *detectorTally) AbsorbFindings(fs []findings.Finding) {
	for _, f := range fs {
		class := classifyDetector(f.Detector)
		if _, ok := t.counts[class]; !ok {
			t.order = append(t.order, class)
		}
		t.counts[class]++
	}
}

// classifyDetector reduces a Finding.Detector value to its family root
// (`heuristic:dep-confusion` → `heuristic`, `hostforensics:tokens` →
// `hostforensics`). Leaves single-segment detectors as-is.
func classifyDetector(d string) string {
	if i := strings.Index(d, ":"); i > 0 {
		return d[:i]
	}
	return d
}

// Print writes the tally to w. Zero-count rows are dimmed when w is
// a TTY (palette derives that). Layout: aligned name column, count
// column, separator bar, total. Empty tally (no rows registered)
// emits nothing. (Named Print rather than WriteTo to avoid colliding
// with the io.WriterTo interface contract; we want a void return.)
func (t *detectorTally) Print(w io.Writer) {
	if len(t.order) == 0 {
		return
	}
	p := newPalette(w)

	// Stable display ordering: registered-order first, then any
	// surprises appended. Within registered-order we keep insertion
	// order because that's the order detectors actually ran.
	// Within "any surprises", sort alphabetically for determinism.
	rows := append([]string(nil), t.order...)
	// Move zero-count rows to the bottom; we want "real signal"
	// at the top.
	sort.SliceStable(rows, func(i, j int) bool {
		ci, cj := t.counts[rows[i]], t.counts[rows[j]]
		if (ci == 0) != (cj == 0) {
			return ci > cj // non-zero first
		}
		if ci != cj {
			return ci > cj
		}
		return rows[i] < rows[j]
	})

	// Compute column width.
	width := 0
	for _, r := range rows {
		if d := displayName(r); len(d) > width {
			width = len(d)
		}
	}
	if width < 30 {
		width = 30
	}

	total := 0
	for _, c := range t.counts {
		total += c
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%sdetectors:%s\n", p.bold, p.reset)
	for _, r := range rows {
		count := t.counts[r]
		label := fmt.Sprintf("  %-*s  %d", width, displayName(r), count)
		if count == 0 {
			fmt.Fprintf(w, "%s%s%s\n", p.gray, label, p.reset)
		} else {
			fmt.Fprintln(w, label)
		}
	}
	fmt.Fprintf(w, "  %s\n", strings.Repeat("-", width+4))
	fmt.Fprintf(w, "  %-*s  %d findings\n", width, "total", total)
	fmt.Fprintln(w)
}

// displayName turns the internal detector class into a more
// human-legible row label.
func displayName(class string) string {
	switch class {
	case "hostforensics":
		return "host-state (credentials, shell rc, persistence)"
	case "incident-pack":
		return "incident-pack (curated IOC matches)"
	case "osv-ioc":
		return "osv-ioc (OSV.dev CVE matches)"
	case "heuristic":
		return "heuristic (evidence-based behavioral detectors)"
	}
	return class
}
