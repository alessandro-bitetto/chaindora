package findings

// FixCategory captures how aggressive automatic remediation can be for a
// given finding. Detectors classify their fixes; the CLI runner decides what
// to apply based on those classifications + user flags.
type FixCategory string

const (
	// FixSafe: applying the fix has well-defined semantics and can't make
	// things meaningfully worse. Example: deleting a file we already know is
	// a worm deployment; upgrading a globally-installed package to its
	// latest stable version. Applied by `--yes`.
	FixSafe FixCategory = "safe"

	// FixSemiSafe: the fix has a clear remediation path but might surprise
	// the user (e.g. uninstalling a package that other things depend on,
	// removing a persistence entry that turns out to be legitimate).
	// Prompted by default; opt-in batch via `--yes --aggressive`.
	FixSemiSafe FixCategory = "semi-safe"

	// FixUnsafe: chaindora can't safely automate this even with consent
	// (requires sudo, requires credentials, etc.). Always prints manual
	// instructions; never executes.
	FixUnsafe FixCategory = "unsafe"

	// FixManual: nothing to execute. The finding requires human judgment
	// (rotate credentials, audit access logs, decide whether a shell rc
	// line is legitimate). Always prints instructions only.
	FixManual FixCategory = "manual"
)

// FixPlan describes how to remediate one Finding. Either Command (executable
// shell command) or ManualSteps (human-readable instructions) — usually one
// or the other; for Unsafe/Manual categories ManualSteps is the only field
// that matters.
type FixPlan struct {
	FindingFingerprint string      `json:"finding_fingerprint"`
	Detector           string      `json:"detector"`
	Severity           Severity    `json:"severity"`
	VulnID             string      `json:"vuln_id"`
	Description        string      `json:"description"`
	Category           FixCategory `json:"category"`
	Command            string      `json:"command,omitempty"`
	ManualSteps        []string    `json:"manual_steps,omitempty"`
}

// Executable reports whether RunFixes can actually invoke a shell to apply
// this plan. Manual / Unsafe plans always return false.
func (p FixPlan) Executable() bool {
	if p.Category == FixManual || p.Category == FixUnsafe {
		return false
	}
	return p.Command != ""
}
