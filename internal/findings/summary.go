package findings

import "time"

// ScanStatus is the terminal state of a scan run. Carried in
// ScanSummary so the receiver can distinguish a clean run from one
// that crashed midway. Borrowed conceptually from bumblebee's
// scan_summary record.
type ScanStatus string

const (
	// ScanStatusComplete — the scan ran to completion and the
	// findings list is the full result. Receivers can promote
	// this run's findings to "current state" for the agent.
	ScanStatusComplete ScanStatus = "complete"
	// ScanStatusPartial — the scan terminated early but produced
	// some findings (timeout, partial detector failure, interrupted
	// by the user). Receivers should NOT promote the findings to
	// current state — the inventory is incomplete and would falsely
	// look like packages were uninstalled. The findings should
	// still be persisted for hunting, just flagged as partial.
	ScanStatusPartial ScanStatus = "partial"
	// ScanStatusError — the scan failed before it could finish.
	// Any findings in the payload are best-effort. Receivers
	// should keep the previous run's "current state" intact.
	ScanStatusError ScanStatus = "error"
)

// ScanSummary is the terminal record of a scan run. Emitted alongside
// findings so receivers (fleet server, log aggregator) can tell whether
// a run completed cleanly. Without this, a scan that crashed midway
// looks identical to a clean scan that happened to find fewer packages
// — and the receiver would silently demote the missing packages from
// "installed" to "uninstalled."
//
// Wire shape is also published at docs/schema/v1/scan-summary.schema.json.
type ScanSummary struct {
	// Status is the terminal state of the run.
	Status ScanStatus `json:"status"`
	// FindingCount is len(findings) at exit. Receivers can compare
	// to the actual payload length as a sanity check.
	FindingCount int `json:"finding_count"`
	// StartedAt is when the scan began. Useful for fleet timeline
	// reconstruction independent of when the payload arrived.
	StartedAt time.Time `json:"started_at"`
	// CompletedAt is when the scan finished (or aborted, for
	// partial/error).
	CompletedAt time.Time `json:"completed_at"`
	// Command is the argv the user ran, for audit trail. Best-effort
	// — may be empty in non-CLI invocations.
	Command string `json:"command,omitempty"`
	// ChdoraVersion is the binary's version. Useful when fleet
	// aggregates show divergent results across agent versions.
	ChdoraVersion string `json:"chdora_version,omitempty"`
	// ErrorMessage, when Status != complete, briefly describes the
	// failure cause. Free-form; renderer prints verbatim.
	ErrorMessage string `json:"error_message,omitempty"`
}

// NewCompleteSummary returns a ScanSummary marked complete, with
// CompletedAt set to now. The common case: a scan finishes without
// error and the caller wants a one-liner constructor.
func NewCompleteSummary(startedAt time.Time, findingCount int, command, version string) ScanSummary {
	return ScanSummary{
		Status:        ScanStatusComplete,
		FindingCount:  findingCount,
		StartedAt:     startedAt,
		CompletedAt:   time.Now().UTC(),
		Command:       command,
		ChdoraVersion: version,
	}
}
