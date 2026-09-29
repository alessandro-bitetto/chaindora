package fixplan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DiskStore persists plans as one JSON file per ID under Dir. The
// directory layout is deliberately flat — one plan, one file — so
// users can `ls`, `cat`, or `rm` them by hand without any chdora
// involvement.
//
// Now is injected for tests; production callers should leave it nil
// and pass time.Now via Default().
type DiskStore struct {
	Dir string
	Now func() time.Time
}

// Default returns a DiskStore rooted at ~/.chaindora/fix-plans/, the
// canonical location used by the CLI commands.
func Default() (*DiskStore, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home dir: %w", err)
	}
	return &DiskStore{
		Dir: filepath.Join(home, ".chaindora", "fix-plans"),
		Now: time.Now,
	}, nil
}

func (s *DiskStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *DiskStore) path(id string) string {
	return filepath.Join(s.Dir, id+".json")
}

// validateID rejects anything that could escape the store directory or
// produce surprising filenames. Plan IDs we generate fit
// `^\d{4}-\d{2}-\d{2}-[0-9a-f]{4}$` but Load/Delete also accept
// hand-typed IDs from the user, so we sanity-check.
func validateID(id string) error {
	if id == "" {
		return errors.New("empty plan id")
	}
	if strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
		return fmt.Errorf("invalid plan id %q", id)
	}
	return nil
}

// Save writes the plan, populating ID and CreatedAt if zero. Returns
// the (possibly-generated) ID. Uses an atomic write — temp file plus
// rename — so a partial write can't corrupt an existing plan.
func (s *DiskStore) Save(plan Plan) (string, error) {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return "", fmt.Errorf("create plan dir: %w", err)
	}
	// When running under sudo, fix ownership on every ancestor of the
	// plan dir we might have just created. Without this, `sudo chdora
	// audit --save-plan` leaves /Users/<u>/.chaindora/ and
	// /Users/<u>/.chaindora/fix-plans/ owned by root, which blocks the
	// non-sudo `chdora plans list` from reading anything underneath.
	chownToSudoUser(s.Dir)
	if parent := filepath.Dir(s.Dir); parent != "" {
		chownToSudoUser(parent)
	}
	if plan.CreatedAt.IsZero() {
		plan.CreatedAt = s.now().UTC()
	}
	if plan.ID == "" {
		id, err := NewID(plan.CreatedAt)
		if err != nil {
			return "", fmt.Errorf("generate plan id: %w", err)
		}
		plan.ID = id
	}
	if err := validateID(plan.ID); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal plan: %w", err)
	}
	tmp, err := os.CreateTemp(s.Dir, ".plan-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create plan temp: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("write plan temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("close plan temp: %w", err)
	}
	if err := os.Rename(tmpPath, s.path(plan.ID)); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("rename plan: %w", err)
	}
	chownToSudoUser(s.path(plan.ID))
	return plan.ID, nil
}

// Load reads the plan back. ErrNotFound for unknown IDs; everything
// else is wrapped with context.
func (s *DiskStore) Load(id string) (Plan, error) {
	if err := validateID(id); err != nil {
		return Plan{}, err
	}
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Plan{}, ErrNotFound
		}
		return Plan{}, fmt.Errorf("read plan %s: %w", id, err)
	}
	var plan Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		return Plan{}, fmt.Errorf("parse plan %s: %w", id, err)
	}
	return plan, nil
}

// List returns metadata-only summaries, sorted most-recent first. Bad
// files in the directory (a user's stray edit, a partial write we
// didn't clean up) are skipped silently rather than failing the whole
// listing — `plans list` should always work even if one plan is
// corrupt.
func (s *DiskStore) List() ([]Summary, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read plan dir: %w", err)
	}
	var summaries []Summary
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if validateID(id) != nil {
			continue
		}
		plan, err := s.Load(id)
		if err != nil {
			continue
		}
		applied := 0
		for _, r := range plan.AppliedResults {
			if r.Status == "applied" {
				applied++
			}
		}
		summaries = append(summaries, Summary{
			ID:            plan.ID,
			CreatedAt:     plan.CreatedAt,
			ScanCommand:   plan.ScanCommand,
			ScanRoot:      plan.ScanRoot,
			TotalFindings: plan.TotalFindings,
			PlanCount:     len(plan.Plans),
			Categories:    plan.Categories(),
			AppliedAt:     plan.AppliedAt,
			AppliedCount:  applied,
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].CreatedAt.After(summaries[j].CreatedAt)
	})
	return summaries, nil
}

// Delete removes one plan. ErrNotFound if it didn't exist — callers
// should treat that as user error, not a silent success, so the user
// doesn't think they cleaned something they didn't.
func (s *DiskStore) Delete(id string) error {
	if err := validateID(id); err != nil {
		return err
	}
	err := os.Remove(s.path(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return fmt.Errorf("delete plan %s: %w", id, err)
	}
	return nil
}

// Prune removes plans whose CreatedAt is older than olderThan ago.
// Useful for cron-style cleanup; the CLI exposes this as
// `chdora plans prune --older-than 30d`.
func (s *DiskStore) Prune(olderThan time.Duration) (int, error) {
	summaries, err := s.List()
	if err != nil {
		return 0, err
	}
	cutoff := s.now().Add(-olderThan)
	deleted := 0
	for _, sm := range summaries {
		if sm.CreatedAt.Before(cutoff) {
			if err := s.Delete(sm.ID); err != nil && !errors.Is(err, ErrNotFound) {
				return deleted, err
			}
			deleted++
		}
	}
	return deleted, nil
}

// MarkApplied records the outcome of executing a plan. Sets
// AppliedAt to s.now() unconditionally — re-applying a plan
// overwrites the previous record because the most recent run is
// what matters for staleness checks.
func (s *DiskStore) MarkApplied(id string, results []AppliedResult) error {
	plan, err := s.Load(id)
	if err != nil {
		return err
	}
	t := s.now().UTC()
	plan.AppliedAt = &t
	plan.AppliedResults = results
	_, err = s.Save(plan)
	return err
}
