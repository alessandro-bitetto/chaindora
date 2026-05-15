package findings

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBaselineRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "baseline.json")

	fs := []Finding{
		{VulnID: "A", Name: "lodash", Version: "4.17.20", Detector: "osv-ioc"},
		{VulnID: "B", Name: "react", Version: "18.0.0", Detector: "osv-ioc"},
	}
	b := BaselineFromFindings(fs, "0.10.0", "2026-05-15T12:00:00Z")
	if len(b.Fingerprints) != 2 {
		t.Errorf("expected 2 fingerprints, got %d", len(b.Fingerprints))
	}
	if err := SaveBaseline(path, b); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Fingerprints) != 2 {
		t.Errorf("round-trip: got %d fingerprints, want 2", len(loaded.Fingerprints))
	}
	if loaded.ChdoraVersion != "0.10.0" {
		t.Errorf("version round-trip: got %q", loaded.ChdoraVersion)
	}
}

func TestLoadBaseline_MissingFileReturnsNil(t *testing.T) {
	b, err := LoadBaseline(filepath.Join(t.TempDir(), "no-such-file.json"))
	if err != nil {
		t.Fatal(err)
	}
	if b != nil {
		t.Errorf("missing file should return nil, got %v", b)
	}
}

func TestDiffAgainstBaseline_NilBaselineAllNew(t *testing.T) {
	fs := []Finding{{VulnID: "X"}, {VulnID: "Y"}}
	newF, removed := DiffAgainstBaseline(fs, nil)
	if len(newF) != 2 {
		t.Errorf("nil baseline → everything is new; got %d new", len(newF))
	}
	if len(removed) != 0 {
		t.Errorf("nil baseline → nothing removed; got %d", len(removed))
	}
}

func TestDiffAgainstBaseline_FindsOnlyNew(t *testing.T) {
	old1 := Finding{VulnID: "A", Name: "x"}
	old2 := Finding{VulnID: "B", Name: "y"}
	new1 := Finding{VulnID: "C", Name: "z"}

	baseline := BaselineFromFindings([]Finding{old1, old2}, "test", "")

	current := []Finding{old1, new1} // old2 resolved, new1 introduced
	newF, removed := DiffAgainstBaseline(current, baseline)
	if len(newF) != 1 || newF[0].VulnID != "C" {
		t.Errorf("new findings: got %v, want [C]", newF)
	}
	if len(removed) != 1 || removed[0] != Fingerprint(old2) {
		t.Errorf("removed: got %v, want [%s]", removed, Fingerprint(old2))
	}
}

func TestBaseline_DeterministicSort(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "b.json")
	fs := []Finding{
		{VulnID: "ZZZ"}, {VulnID: "AAA"}, {VulnID: "MMM"},
	}
	b := BaselineFromFindings(fs, "0.10.0", "")
	if err := SaveBaseline(path, b); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	// Reload and confirm sorted.
	loaded, _ := LoadBaseline(path)
	for i := 1; i < len(loaded.Fingerprints); i++ {
		if loaded.Fingerprints[i-1] > loaded.Fingerprints[i] {
			t.Errorf("fingerprints not sorted on disk: %v", loaded.Fingerprints)
		}
	}
	_ = data
}

func TestBaselineFromFindings_DedupesIdenticalFingerprints(t *testing.T) {
	f := Finding{VulnID: "A", Name: "x", Version: "1.0"}
	b := BaselineFromFindings([]Finding{f, f, f}, "test", "")
	if len(b.Fingerprints) != 1 {
		t.Errorf("dedupe: got %d, want 1", len(b.Fingerprints))
	}
}
