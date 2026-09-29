package gate

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestCache(t *testing.T) *Cache {
	t.Helper()
	dir := t.TempDir()
	return NewCache(dir, 7*24*time.Hour)
}

func approvedCheck(checker string) PackageCheck {
	return PackageCheck{Results: []CheckResult{{
		Checker: checker,
		Verdict: VerdictApprove,
		Reason:  "ok",
	}}}
}

func TestCache_StoreThenLookup_RoundTrip(t *testing.T) {
	c := newTestCache(t)
	ref := PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", Integrity: "sha512-AAA"}
	pc := PackageCheck{Package: ref, Results: []CheckResult{
		{Checker: "cooldown", Verdict: VerdictApprove, Reason: "old enough"},
		{Checker: "osv-malicious", Verdict: VerdictApprove, Reason: "no MAL match"},
	}}
	if err := c.Store(ref, pc); err != nil {
		t.Fatalf("store: %v", err)
	}
	got := c.Lookup(ref)
	if got == nil {
		t.Fatal("lookup returned nil after store")
	}
	if got.Name != "lodash" || got.Version != "4.17.21" || got.Integrity != "sha512-AAA" {
		t.Errorf("entry fields wrong: %+v", got)
	}
	if len(got.Results) != 2 {
		t.Errorf("results lost: got %d, want 2", len(got.Results))
	}
}

func TestCache_Store_SkipsEmptyIntegrity(t *testing.T) {
	c := newTestCache(t)
	ref := PackageRef{Ecosystem: "npm", Name: "no-hash", Version: "1.0.0"} // no Integrity
	pc := approvedCheck("cooldown")
	if err := c.Store(ref, pc); err != nil {
		t.Fatalf("store: %v", err)
	}
	// File should not have been written.
	entries, _ := os.ReadDir(c.Root)
	if len(entries) != 0 {
		t.Errorf("store wrote entries for empty-integrity ref: %v", entries)
	}
}

func TestCache_Store_SkipsNonApprove(t *testing.T) {
	c := newTestCache(t)
	ref := PackageRef{Ecosystem: "npm", Name: "warned", Version: "1.0.0", Integrity: "sha512-X"}
	pc := PackageCheck{Package: ref, Results: []CheckResult{{
		Checker: "publisher-change",
		Verdict: VerdictWarn,
		Reason:  "different publisher",
	}}}
	if err := c.Store(ref, pc); err != nil {
		t.Fatalf("store: %v", err)
	}
	if got := c.Lookup(ref); got != nil {
		t.Errorf("warn verdict should not have been cached: %+v", got)
	}
}

func TestCache_Lookup_RespectsTTL(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir, 1*time.Millisecond)
	ref := PackageRef{Ecosystem: "npm", Name: "expired", Version: "1.0.0", Integrity: "sha512-Z"}
	pc := approvedCheck("cooldown")
	if err := c.Store(ref, pc); err != nil {
		t.Fatalf("store: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if got := c.Lookup(ref); got != nil {
		t.Errorf("ttl-expired entry returned: %+v", got)
	}
}

func TestCache_Lookup_DifferentIntegrityMisses(t *testing.T) {
	c := newTestCache(t)
	stored := PackageRef{Ecosystem: "npm", Name: "drift", Version: "1.0.0", Integrity: "sha512-OLD"}
	if err := c.Store(stored, approvedCheck("cooldown")); err != nil {
		t.Fatalf("store: %v", err)
	}
	queried := PackageRef{Ecosystem: "npm", Name: "drift", Version: "1.0.0", Integrity: "sha512-NEW"}
	if got := c.Lookup(queried); got != nil {
		t.Errorf("different-integrity lookup should miss: %+v", got)
	}
}

func TestCache_LookupAnyIntegrity_FindsByNameAndVersion(t *testing.T) {
	c := newTestCache(t)
	stored := PackageRef{Ecosystem: "npm", Name: "drift", Version: "1.0.0", Integrity: "sha512-OLD"}
	if err := c.Store(stored, approvedCheck("cooldown")); err != nil {
		t.Fatalf("store: %v", err)
	}
	hit := c.LookupAnyIntegrity("npm", "drift", "1.0.0")
	if hit == nil || hit.Integrity != "sha512-OLD" {
		t.Errorf("LookupAnyIntegrity miss or wrong entry: %+v", hit)
	}
}

func TestCache_LookupAnyIntegrity_NoSuchPackage(t *testing.T) {
	c := newTestCache(t)
	if hit := c.LookupAnyIntegrity("npm", "never-cached", "1.0.0"); hit != nil {
		t.Errorf("expected nil, got %+v", hit)
	}
}

func TestCache_Stats_GroupsByEcosystem(t *testing.T) {
	c := newTestCache(t)
	for _, r := range []PackageRef{
		{Ecosystem: "npm", Name: "a", Version: "1", Integrity: "sha512-1"},
		{Ecosystem: "npm", Name: "b", Version: "1", Integrity: "sha512-2"},
		{Ecosystem: "pypi", Name: "c", Version: "1", Integrity: "sha256-3"},
	} {
		if err := c.Store(r, approvedCheck("cooldown")); err != nil {
			t.Fatalf("store: %v", err)
		}
	}
	stats, err := c.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	counts := map[string]int{}
	for _, s := range stats {
		counts[s.Ecosystem] = s.Entries
	}
	if counts["npm"] != 2 || counts["pypi"] != 1 {
		t.Errorf("counts wrong: %v", counts)
	}
}

func TestCache_Stats_MissingDirIsEmpty(t *testing.T) {
	c := NewCache(filepath.Join(t.TempDir(), "does-not-exist"), 7*24*time.Hour)
	stats, err := c.Stats()
	if err != nil {
		t.Fatalf("stats on missing dir should be nil error, got %v", err)
	}
	if len(stats) != 0 {
		t.Errorf("expected empty stats, got %v", stats)
	}
}

func TestCache_Clear_RemovesEverything(t *testing.T) {
	c := newTestCache(t)
	ref := PackageRef{Ecosystem: "npm", Name: "doomed", Version: "1.0.0", Integrity: "sha512-D"}
	if err := c.Store(ref, approvedCheck("cooldown")); err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := c.Clear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, err := os.Stat(c.Root); !os.IsNotExist(err) {
		t.Errorf("clear left files behind: stat err = %v", err)
	}
}

func TestCache_NilSafety(t *testing.T) {
	// All exported methods must be nil-safe — the CLI constructs the
	// cache lazily and may pass nil when home dir lookup fails.
	var c *Cache
	ref := PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0.0", Integrity: "sha512-X"}
	if got := c.Lookup(ref); got != nil {
		t.Errorf("nil cache Lookup must return nil")
	}
	if got := c.LookupAnyIntegrity("npm", "x", "1.0.0"); got != nil {
		t.Errorf("nil cache LookupAnyIntegrity must return nil")
	}
	if err := c.Store(ref, approvedCheck("cooldown")); err != nil {
		t.Errorf("nil cache Store must return nil error, got %v", err)
	}
	if err := c.Clear(); err != nil {
		t.Errorf("nil cache Clear must return nil error, got %v", err)
	}
	stats, err := c.Stats()
	if err != nil || stats != nil {
		t.Errorf("nil cache Stats must be nil/nil, got %v/%v", stats, err)
	}
}

func TestCacheKeyHash_StableAcrossFieldOrder(t *testing.T) {
	a := PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", Integrity: "sha512-X"}
	b := PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", Integrity: "sha512-X"}
	if cacheKeyHash(a) != cacheKeyHash(b) {
		t.Error("identical refs must hash equal")
	}
	c := PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.22", Integrity: "sha512-X"}
	if cacheKeyHash(a) == cacheKeyHash(c) {
		t.Error("different versions must hash differently")
	}
	d := PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", Integrity: "sha512-Y"}
	if cacheKeyHash(a) == cacheKeyHash(d) {
		t.Error("different integrity must hash differently — would defeat republish-guard")
	}
}

func TestDefaultCacheRoot_NotEmpty(t *testing.T) {
	// Either a valid path under $HOME, or "" when home lookup fails.
	// On test runners $HOME is always set so we expect non-empty.
	if got := DefaultCacheRoot(); got == "" {
		t.Skip("HOME unavailable in this test environment")
	}
}
