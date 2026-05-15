package fixplan

import (
	"testing"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

func TestNewID_DateInPrefix(t *testing.T) {
	now := time.Date(2026, 5, 15, 17, 0, 0, 0, time.UTC)
	id, err := NewID(now)
	if err != nil {
		t.Fatal(err)
	}
	if got := id[:10]; got != "2026-05-15" {
		t.Errorf("id prefix: got %q, want 2026-05-15", got)
	}
	if len(id) != 15 {
		t.Errorf("id length: got %d, want 15 (date + dash + 4 hex)", len(id))
	}
}

func TestDiskStoreSaveAndLoad(t *testing.T) {
	tmp := t.TempDir()
	store := &DiskStore{Dir: tmp, Now: func() time.Time {
		return time.Date(2026, 5, 15, 17, 0, 0, 0, time.UTC)
	}}
	plan := Plan{
		ScanCommand:   "chdora audit --whole-machine",
		ScanRoot:      "/",
		TotalFindings: 187,
		Plans: []findings.FixPlan{
			{VulnID: "CVE-2026-1234", Category: findings.FixSemiSafe, Command: "echo ok"},
			{VulnID: "CVE-2026-5678", Category: findings.FixManual},
		},
	}
	id, err := store.Save(plan)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("save returned empty id")
	}
	if got := id[:10]; got != "2026-05-15" {
		t.Errorf("id should carry today's date: got %q", id)
	}

	loaded, err := store.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ScanCommand != plan.ScanCommand {
		t.Errorf("ScanCommand round-trip: got %q", loaded.ScanCommand)
	}
	if len(loaded.Plans) != 2 {
		t.Errorf("plans round-trip: got %d", len(loaded.Plans))
	}
	if loaded.CreatedAt.IsZero() {
		t.Errorf("CreatedAt should be auto-populated on Save")
	}
}

func TestDiskStoreList_OrdersMostRecentFirst(t *testing.T) {
	tmp := t.TempDir()
	day1 := time.Date(2026, 5, 14, 17, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 5, 15, 17, 0, 0, 0, time.UTC)

	store := &DiskStore{Dir: tmp, Now: func() time.Time { return day1 }}
	id1, _ := store.Save(Plan{ScanCommand: "first"})
	store.Now = func() time.Time { return day2 }
	id2, _ := store.Save(Plan{ScanCommand: "second"})

	summaries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(summaries))
	}
	if summaries[0].ID != id2 {
		t.Errorf("expected most-recent first: got %v", summaries[0].ID)
	}
	if summaries[1].ID != id1 {
		t.Errorf("expected oldest last: got %v", summaries[1].ID)
	}
}

func TestDiskStoreDelete(t *testing.T) {
	tmp := t.TempDir()
	store := &DiskStore{Dir: tmp, Now: time.Now}
	id, _ := store.Save(Plan{ScanCommand: "x"})

	if err := store.Delete(id); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(id); err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
	if err := store.Delete(id); err != ErrNotFound {
		t.Errorf("double-delete should return ErrNotFound, got %v", err)
	}
}

func TestDiskStorePrune(t *testing.T) {
	tmp := t.TempDir()
	now := time.Date(2026, 5, 15, 17, 0, 0, 0, time.UTC)
	store := &DiskStore{Dir: tmp, Now: func() time.Time { return now }}

	store.Now = func() time.Time { return now.AddDate(0, 0, -60) }
	old, _ := store.Save(Plan{ScanCommand: "old"})
	store.Now = func() time.Time { return now }
	fresh, _ := store.Save(Plan{ScanCommand: "fresh"})

	deleted, err := store.Prune(30 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 pruned, got %d", deleted)
	}
	if _, err := store.Load(old); err != ErrNotFound {
		t.Errorf("old plan should be gone")
	}
	if _, err := store.Load(fresh); err != nil {
		t.Errorf("fresh plan should remain: %v", err)
	}
}

func TestMarkApplied(t *testing.T) {
	tmp := t.TempDir()
	store := &DiskStore{Dir: tmp, Now: time.Now}
	id, _ := store.Save(Plan{Plans: []findings.FixPlan{
		{VulnID: "A"}, {VulnID: "B"}, {VulnID: "C"},
	}})
	results := []AppliedResult{
		{FixIndex: 0, VulnID: "A", Status: "applied"},
		{FixIndex: 1, VulnID: "B", Status: "failed"},
		{FixIndex: 2, VulnID: "C", Status: "skipped"},
	}
	if err := store.MarkApplied(id, results); err != nil {
		t.Fatal(err)
	}
	loaded, _ := store.Load(id)
	if loaded.AppliedAt == nil {
		t.Errorf("AppliedAt should be set")
	}
	if len(loaded.AppliedResults) != 3 {
		t.Errorf("results: got %d", len(loaded.AppliedResults))
	}

	summaries, _ := store.List()
	if len(summaries) == 0 {
		t.Fatal("no summaries")
	}
	if summaries[0].Status() != "partial" {
		t.Errorf("status: got %q, want partial (1/3 applied)", summaries[0].Status())
	}
	if summaries[0].AppliedCount != 1 {
		t.Errorf("applied count: got %d, want 1", summaries[0].AppliedCount)
	}
}

func TestCategories(t *testing.T) {
	p := Plan{Plans: []findings.FixPlan{
		{Category: findings.FixSafe},
		{Category: findings.FixSemiSafe},
		{Category: findings.FixSemiSafe},
		{Category: findings.FixManual},
		{Category: findings.FixUnsafe},
	}}
	c := p.Categories()
	if c.Safe != 1 || c.SemiSafe != 2 || c.Manual != 1 || c.Unsafe != 1 {
		t.Errorf("category counts: %+v", c)
	}
}

func TestValidateID_RejectsPathTraversal(t *testing.T) {
	for _, bad := range []string{"", "../etc/passwd", "a/b", `a\b`, "..", "2026-05-15-../evil"} {
		if err := validateID(bad); err == nil {
			t.Errorf("expected rejection for %q", bad)
		}
	}
	for _, good := range []string{"2026-05-15-a3f2", "test-id"} {
		if err := validateID(good); err != nil {
			t.Errorf("unexpected rejection for %q: %v", good, err)
		}
	}
}
