package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/fixplan"
)

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
