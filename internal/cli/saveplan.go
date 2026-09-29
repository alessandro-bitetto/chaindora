package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/fixplan"
)

// isInteractiveTTY reports whether stdin looks like an attached
// terminal (i.e. there's a human ready to type a reply). We check
// the mode bits rather than pulling in golang.org/x/term because the
// project keeps its external-dep footprint to two libraries.
func isInteractiveTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// saveFixPlan persists the supplied plans under a fresh ID and returns
// the ID for the caller to surface to the user. fixPlans coming from
// buildAllFixPlans are passed through verbatim — staleness checks and
// dedup happen at apply time, not save time, so the same plan can be
// safely re-applied against a moved-forward worktree.
func saveFixPlan(plans []findings.FixPlan, totalFindings int, scanRoot string) (string, error) {
	store, err := fixplan.Default()
	if err != nil {
		return "", err
	}
	id, err := store.Save(fixplan.Plan{
		ChdoraVersion: Version,
		ScanCommand:   strings.Join(os.Args, " "),
		ScanRoot:      scanRoot,
		TotalFindings: totalFindings,
		Plans:         plans,
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

// emitEndOfRunFooter is the gentle nudge shown after a scan / audit /
// ci / forensics run when there are fixes available but nothing was
// done with them. Three actionable paths, one line each — no
// flag-soup, no "see --help for more." If the user already passed
// --fix or --save-plan, we skip it (they're not the audience).
//
// The footer goes to stderr so it doesn't pollute --format=json piping
// downstream.
func emitEndOfRunFooter(w io.Writer, plans []findings.FixPlan, saved bool, savedID string, fixRequested bool) {
	if len(plans) == 0 {
		return
	}
	if saved {
		// "save and apply now" combination message — and the
		// follow-up apply hint that uses the just-printed ID.
		if !fixRequested {
			fmt.Fprintf(w, "\n[chdora] %d fix(es) saved to plan %s\n", len(plans), savedID)
			fmt.Fprintf(w, "  → apply later:       chdora fix --plan %s --yes\n", savedID)
			fmt.Fprintf(w, "  → apply with semi-safe: chdora fix --plan %s --yes --aggressive\n", savedID)
			fmt.Fprintf(w, "  → list saved plans:  chdora plans list\n")
		}
		return
	}
	if fixRequested {
		return
	}
	// Plain "fixes available but nothing was done" case.
	fmt.Fprintf(w, "\n[chdora] %d fix(es) available — none applied. Options:\n", len(plans))
	fmt.Fprintf(w, "  → save for later:    re-run with --save-plan\n")
	fmt.Fprintf(w, "  → apply now:         re-run with --fix --yes --fix-aggressive\n")
	fmt.Fprintf(w, "  → save AND apply:    re-run with --save-plan --fix --yes\n")
}

// maybePromptSavePlan offers an interactive save when the run ended
// with fixes available but the user didn't ask for any (no
// --save-plan, no --fix). Returns the saved plan ID if the user
// agreed and the save succeeded; otherwise "".
//
// Skipped silently when stdin isn't a TTY (so CI pipelines and
// `chdora audit | jq` keep working), or when the caller already
// handled fixes another way (saved=true || fixRequested=true).
//
// The prompt defaults to Yes — pressing Enter saves, which matches
// the design intent ("at the end of each audit, we ask the user if
// they want a produced fix-plan-id; if yes, save it"). Anything
// starting with 'n' or 'N' declines; everything else is treated as
// consent.
func maybePromptSavePlan(stdin io.Reader, stderr io.Writer,
	plans []findings.FixPlan, totalFindings int, scanRoot string,
	saved, fixRequested bool) string {
	if saved || fixRequested {
		return ""
	}
	if len(plans) == 0 {
		return ""
	}
	if stdin == nil {
		stdin = os.Stdin
	}
	// Honor non-interactive callers: when stdin isn't a real
	// terminal, fall back to the footer instead of blocking on a
	// prompt that nobody will answer.
	if f, ok := stdin.(*os.File); ok && f == os.Stdin && !isInteractiveTTY() {
		return ""
	}

	fmt.Fprintf(stderr, "\n[chdora] %d fix(es) available. Save them as a plan to apply later? [Y/n] ", len(plans))
	br := bufio.NewReader(stdin)
	line, err := br.ReadString('\n')
	if err != nil && line == "" {
		// EOF / read error — fail open: don't save, print the
		// footer so the user has the same info as before.
		return ""
	}
	answer := strings.TrimSpace(strings.ToLower(line))
	if strings.HasPrefix(answer, "n") {
		return ""
	}
	id, err := saveFixPlan(plans, totalFindings, scanRoot)
	if err != nil {
		fmt.Fprintf(stderr, "[chdora] failed to save plan: %v\n", err)
		return ""
	}
	// Don't print the save-success block here; the caller's
	// emitEndOfRunFooter handles that uniformly with the
	// --save-plan flag path.
	return id
}
