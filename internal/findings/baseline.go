package findings

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Baseline is the persisted set of findings from a prior scan,
// used by CI to surface ONLY new findings on a PR rather than
// every pre-existing one. Stored as a flat list of Fingerprints
// — small, diff-friendly under git, and immune to wrapping
// changes in the full Finding shape.
//
// Designed so the baseline file can be committed to the repo.
// The hash of every kept finding plus a top-level metadata block
// (when, by what version) is enough for review while keeping
// the diff readable on PR.
type Baseline struct {
	// Version of the chdora binary that wrote this baseline.
	// Surfaced in mismatch warnings (different chdora versions
	// can produce different fingerprints for the same finding,
	// rare but possible across a major-version-bump finding-
	// schema change).
	ChdoraVersion string `json:"chdora_version"`

	// CreatedAt is when this baseline was written.
	CreatedAt string `json:"created_at,omitempty"`

	// Fingerprints is the set of finding hashes recorded at
	// baseline time. Used as a "known and accepted" gate.
	// Order is deterministic-sorted on write for git-friendly
	// diffs.
	Fingerprints []string `json:"fingerprints"`
}

// fingerprintSet builds a set from Fingerprints for O(1) lookup.
func (b *Baseline) fingerprintSet() map[string]struct{} {
	out := make(map[string]struct{}, len(b.Fingerprints))
	for _, fp := range b.Fingerprints {
		out[fp] = struct{}{}
	}
	return out
}

// LoadBaseline reads a baseline file. Returns nil + nil when no
// file exists at the path (first-run case — CI should treat that
// as "no baseline, every finding is new, write the baseline
// after the run").
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &b, nil
}

// SaveBaseline writes the baseline atomically (temp-file +
// rename) so a partial write can't corrupt an existing
// baseline. The Fingerprints slice is sorted before writing for
// reproducible diffs.
func SaveBaseline(path string, b *Baseline) error {
	if b == nil {
		return errors.New("nil baseline")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	// Sort for deterministic output. Already de-duplicated by
	// the caller via BaselineFromFindings.
	sortedFingerprints(b.Fingerprints)
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".baseline-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

// BaselineFromFindings builds a Baseline from a current findings
// list. De-duplicates fingerprints (the same finding can be
// reported under multiple paths in rare cases) and stamps the
// supplied chdora version + timestamp.
func BaselineFromFindings(fs []Finding, chdoraVersion string, createdAt string) *Baseline {
	seen := make(map[string]struct{}, len(fs))
	fps := make([]string, 0, len(fs))
	for _, f := range fs {
		fp := Fingerprint(f)
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		fps = append(fps, fp)
	}
	return &Baseline{
		ChdoraVersion: chdoraVersion,
		CreatedAt:     createdAt,
		Fingerprints:  fps,
	}
}

// DiffAgainstBaseline returns (new, removed) — findings whose
// fingerprint isn't in the baseline (new this scan) and
// fingerprints in the baseline that no longer appear in the
// current findings (resolved since baseline). Removed is
// surfaced so CI can OPTIONALLY warn on baseline drift if the
// user wants the baseline to track current state.
func DiffAgainstBaseline(current []Finding, b *Baseline) (newFindings []Finding, removed []string) {
	if b == nil {
		// No baseline yet — everything is new.
		return current, nil
	}
	known := b.fingerprintSet()
	currentSet := make(map[string]struct{}, len(current))
	for _, f := range current {
		fp := Fingerprint(f)
		currentSet[fp] = struct{}{}
		if _, ok := known[fp]; !ok {
			newFindings = append(newFindings, f)
		}
	}
	for fp := range known {
		if _, ok := currentSet[fp]; !ok {
			removed = append(removed, fp)
		}
	}
	return newFindings, removed
}

// sortedFingerprints sorts a fingerprint slice in place,
// alphabetical order. Surfaced as a separate function so tests
// can verify the sort is stable across runs (deterministic
// diff is the whole point of writing the baseline).
func sortedFingerprints(fps []string) {
	// Use a tiny insertion sort — fingerprints are short fixed
	// strings, the list is usually under a few hundred entries,
	// and avoiding a stdlib sort import keeps this file leaf-y.
	for i := 1; i < len(fps); i++ {
		key := fps[i]
		j := i - 1
		for j >= 0 && fps[j] > key {
			fps[j+1] = fps[j]
			j--
		}
		fps[j+1] = key
	}
}
