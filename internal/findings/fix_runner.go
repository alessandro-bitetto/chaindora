package findings

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// RunOptions configures how RunFixes treats a slice of plans.
type RunOptions struct {
	// PlanOnly prints each plan and returns without prompting or executing.
	PlanOnly bool

	// AutoYes applies every plan whose Category is in AllowedCategories
	// without prompting. The runner still skips Manual / Unsafe plans
	// (those never execute).
	AutoYes bool

	// AllowedCategories filters which categories are eligible for
	// auto-apply under AutoYes. Defaults to {FixSafe}.
	AllowedCategories []FixCategory

	// Stdin lets tests inject input. Falls back to os.Stdin.
	Stdin io.Reader

	// Output is where the runner writes its diagnostic messages and the
	// stdout/stderr of executed commands. Falls back to os.Stderr.
	Output io.Writer
}

// RunFixes evaluates plans, optionally prompts, and executes Commands. Returns
// the count of applied vs. skipped plus the first execution error encountered.
func RunFixes(ctx context.Context, plans []FixPlan, opts RunOptions) (applied, skipped int, err error) {
	out := opts.Output
	if out == nil {
		out = os.Stderr
	}
	in := bufio.NewReader(stdinOr(opts.Stdin))
	allowed := opts.AllowedCategories
	if len(allowed) == 0 {
		allowed = []FixCategory{FixSafe}
	}

	plans = dedupePlansByCommand(plans)
	if len(plans) == 0 {
		fmt.Fprintln(out, "no fixable findings")
		return 0, 0, nil
	}
	fmt.Fprintf(out, "\n=== %d fix plan(s) ===\n", len(plans))

	autoApplyRest := false
	for i, p := range plans {
		printPlan(out, i+1, len(plans), p)

		if opts.PlanOnly {
			continue
		}
		if !p.Executable() {
			skipped++
			continue
		}

		shouldApply := false
		switch {
		case autoApplyRest:
			shouldApply = true
		case opts.AutoYes && categoryAllowed(p.Category, allowed):
			shouldApply = true
		default:
			choice := promptFix(out, in)
			switch choice {
			case "a":
				shouldApply = true
			case "A":
				shouldApply = true
				autoApplyRest = true
			case "q":
				fmt.Fprintln(out, "aborted by user")
				return applied, skipped, nil
			default:
				skipped++
				continue
			}
		}

		if !shouldApply {
			skipped++
			continue
		}
		fmt.Fprintf(out, "  applying: %s\n", p.Command)
		if execErr := executeCommand(ctx, p.Command, out); execErr != nil {
			fmt.Fprintf(out, "  FAILED: %v\n", execErr)
			skipped++
			if err == nil {
				err = execErr
			}
			continue
		}
		applied++
		fmt.Fprintln(out, "  ok")
	}

	fmt.Fprintf(out, "\nfixes: applied=%d, skipped=%d\n", applied, skipped)
	return applied, skipped, err
}

func printPlan(w io.Writer, n, total int, p FixPlan) {
	fmt.Fprintf(w, "\nFix %d/%d  [%s] [%s] %s\n", n, total, p.Severity, p.Category, p.VulnID)
	fmt.Fprintf(w, "  %s\n", p.Description)
	if p.Command != "" {
		fmt.Fprintf(w, "  command: %s\n", p.Command)
	}
	for _, s := range p.ManualSteps {
		fmt.Fprintf(w, "  step: %s\n", s)
	}
}

func categoryAllowed(c FixCategory, allowed []FixCategory) bool {
	for _, a := range allowed {
		if a == c {
			return true
		}
	}
	return false
}

func promptFix(w io.Writer, r *bufio.Reader) string {
	fmt.Fprint(w, "  [a]pply  [s]kip  [A]pply all remaining  [q]uit > ")
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "q"
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "s"
	}
	// Preserve case for the capital-A "apply all" affordance
	return string(line[0])
}

// executeCommand runs the plan's shell command via `sh -c` on Unix. Windows
// is currently a no-op: --fix prints the command and skips execution, with
// guidance to run it manually in PowerShell or cmd.
func executeCommand(ctx context.Context, cmd string, out io.Writer) error {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(out, "  (Windows: automated execution not yet supported — run the command manually)")
		return nil
	}
	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	c.Stdout = out
	c.Stderr = out
	return c.Run()
}

func stdinOr(r io.Reader) io.Reader {
	if r != nil {
		return r
	}
	return os.Stdin
}

// dedupePlansByCommand collapses identical executable Commands so we don't
// re-run `python3 -m pip install --upgrade pip` once per pip CVE. Manual /
// command-less plans pass through untouched — each finding keeps its own
// remediation steps. Highest-severity finding wins for the kept entry so
// the user sees the strongest justification.
func dedupePlansByCommand(plans []FixPlan) []FixPlan {
	seen := map[string]int{}
	out := make([]FixPlan, 0, len(plans))
	for _, p := range plans {
		if p.Command == "" {
			out = append(out, p)
			continue
		}
		if idx, ok := seen[p.Command]; ok {
			if severityRank(p.Severity) > severityRank(out[idx].Severity) {
				out[idx].Severity = p.Severity
				out[idx].VulnID = p.VulnID
				out[idx].Description = p.Description
			}
			continue
		}
		seen[p.Command] = len(out)
		out = append(out, p)
	}
	return out
}

func severityRank(s Severity) int {
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
