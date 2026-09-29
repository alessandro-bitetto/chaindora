// Package fixplan stores and replays chdora fix plans. The point: decouple
// "what should be fixed" (produced by `chdora scan` / `audit`) from "go
// fix it" (`chdora fix --plan <id>`) so the two can happen in different
// terminals, on different days, by different people.
//
// Plans live as one JSON file per ID under ~/.chaindora/fix-plans/. IDs
// are short, human-readable (YYYY-MM-DD-<4hex>) and stable enough to
// paste into a Slack message or a ticket. The file is safe to delete by
// hand; nothing else depends on its existence.
package fixplan

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// Plan is one persisted fix-plan artifact — a snapshot of "here's
// everything chdora would fix if you ran --fix right now," plus enough
// metadata to render a useful list view and to recognize the plan as
// stale (current state has moved past what the plan was built against).
type Plan struct {
	ID              string             `json:"id"`
	CreatedAt       time.Time          `json:"created_at"`
	ChdoraVersion   string             `json:"chdora_version"`
	ScanCommand     string             `json:"scan_command,omitempty"`
	ScanRoot        string             `json:"scan_root,omitempty"`
	TotalFindings   int                `json:"total_findings"`
	Plans           []findings.FixPlan `json:"plans"`
	AppliedAt       *time.Time         `json:"applied_at,omitempty"`
	AppliedResults  []AppliedResult    `json:"applied_results,omitempty"`
}

// AppliedResult records the outcome of one plan execution. Persisted
// alongside the plan so `chdora plans show` can render "47/246 already
// applied" without re-running anything, and so re-applying the plan
// (e.g. after restoring from git stash) can skip already-applied fixes
// instead of re-running them.
type AppliedResult struct {
	FixIndex   int       `json:"fix_index"`
	VulnID     string    `json:"vuln_id"`
	Status     string    `json:"status"` // applied | failed | skipped | no-op | already-satisfied
	AppliedAt  time.Time `json:"applied_at"`
	StderrTail string    `json:"stderr_tail,omitempty"`
}

// CategoryCounts breaks down Plan.Plans by FixCategory — useful for
// list views where we want "114 auto-applicable + 132 manual" at a
// glance without loading the full plan.
type CategoryCounts struct {
	Safe     int `json:"safe"`
	SemiSafe int `json:"semi_safe"`
	Unsafe   int `json:"unsafe"`
	Manual   int `json:"manual"`
}

// Categories returns per-FixCategory counts for the plan's fix list.
func (p Plan) Categories() CategoryCounts {
	var c CategoryCounts
	for _, fp := range p.Plans {
		switch fp.Category {
		case findings.FixSafe:
			c.Safe++
		case findings.FixSemiSafe:
			c.SemiSafe++
		case findings.FixUnsafe:
			c.Unsafe++
		case findings.FixManual:
			c.Manual++
		}
	}
	return c
}

// Summary is the metadata-only view used by `chdora plans list`. Cheap
// to load (no fix-plan body), suitable for tabular rendering of many
// plans at once.
type Summary struct {
	ID            string         `json:"id"`
	CreatedAt     time.Time      `json:"created_at"`
	ScanCommand   string         `json:"scan_command"`
	ScanRoot      string         `json:"scan_root"`
	TotalFindings int            `json:"total_findings"`
	PlanCount     int            `json:"plan_count"`
	Categories    CategoryCounts `json:"categories"`
	AppliedAt     *time.Time     `json:"applied_at,omitempty"`
	AppliedCount  int            `json:"applied_count"`
}

// Status is a one-word description of the plan's state, suitable for
// the rightmost column of `plans list`.
func (s Summary) Status() string {
	if s.AppliedAt == nil {
		return "unapplied"
	}
	if s.AppliedCount >= s.PlanCount {
		return "applied"
	}
	return "partial"
}

// Store is the persistence interface. The CLI binds to this so tests
// can swap in a memory-backed store without writing files.
type Store interface {
	Save(plan Plan) (string, error)
	Load(id string) (Plan, error)
	List() ([]Summary, error)
	Delete(id string) error
	Prune(olderThan time.Duration) (deleted int, err error)
	MarkApplied(id string, results []AppliedResult) error
}

// ErrNotFound is returned by Load / Delete / MarkApplied for an unknown
// plan ID. Callers should produce a user-friendly message rather than
// surfacing this directly.
var ErrNotFound = errors.New("plan not found")

// NewID builds a fresh plan ID in the form YYYY-MM-DD-<4-hex>. Date
// makes the ID self-describing; the hex suffix prevents same-day
// collisions when an audit runs multiple times. Tests can replace
// crypto/rand.Reader to make IDs deterministic.
func NewID(now time.Time) (string, error) {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return now.UTC().Format("2006-01-02") + "-" + hex.EncodeToString(buf[:]), nil
}
