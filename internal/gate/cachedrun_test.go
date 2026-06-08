package gate

import (
	"context"
	"sync/atomic"
	"testing"
)

// scriptedChecker returns a fixed verdict on every call. Used to assert
// CachedRun's republish-guard / exact-hit / fallthrough branches in
// isolation from real checker behavior. calls is atomic so the
// concurrency tests (Run / CachedRun fan out across goroutines) don't
// race the test harness.
type scriptedChecker struct {
	name   string
	result CheckResult
	calls  int64 // atomic
}

func (s *scriptedChecker) Name() string { return s.name }
func (s *scriptedChecker) Check(ctx context.Context, ref PackageRef) CheckResult {
	atomic.AddInt64(&s.calls, 1)
	return s.result
}

func (s *scriptedChecker) callCount() int64 { return atomic.LoadInt64(&s.calls) }

func TestCachedRun_NilCache_FallsBackToRun(t *testing.T) {
	checker := &scriptedChecker{name: "cooldown", result: CheckResult{
		Checker: "cooldown", Verdict: VerdictApprove, Reason: "ok",
	}}
	refs := []PackageRef{{Ecosystem: "npm", Name: "a", Version: "1.0.0"}}
	got := CachedRun(context.Background(), []Checker{checker}, refs, nil)
	if len(got) != 1 || got[0].Decision() != VerdictApprove {
		t.Fatalf("expected single approve, got %+v", got)
	}
	if checker.callCount() != 1 {
		t.Errorf("checker should run once even with nil cache; calls=%d", checker.callCount())
	}
}

func TestCachedRun_ExactHit_SkipsChecker(t *testing.T) {
	c := newTestCache(t)
	ref := PackageRef{Ecosystem: "npm", Name: "cached", Version: "1.0.0", Integrity: "sha512-A"}
	// Prime the cache with an approve.
	if err := c.Store(ref, PackageCheck{Package: ref, Results: []CheckResult{{
		Checker: "cooldown", Verdict: VerdictApprove, Reason: "cached",
	}}}); err != nil {
		t.Fatalf("store: %v", err)
	}

	checker := &scriptedChecker{name: "cooldown", result: CheckResult{
		Checker: "cooldown", Verdict: VerdictBlock, Reason: "wouldnt-run",
	}}
	got := CachedRun(context.Background(), []Checker{checker}, []PackageRef{ref}, c)
	if len(got) != 1 || got[0].Decision() != VerdictApprove {
		t.Fatalf("cached approve must be returned without re-running checker; got %+v", got)
	}
	if checker.callCount() != 0 {
		t.Errorf("checker must NOT run on cache hit; calls=%d", checker.callCount())
	}
}

func TestCachedRun_RepublishGuard_BlocksDifferentIntegrity(t *testing.T) {
	c := newTestCache(t)
	stored := PackageRef{Ecosystem: "npm", Name: "republished", Version: "1.0.0", Integrity: "sha512-ORIGINAL"}
	if err := c.Store(stored, PackageCheck{Package: stored, Results: []CheckResult{{
		Checker: "cooldown", Verdict: VerdictApprove, Reason: "first install was clean",
	}}}); err != nil {
		t.Fatalf("store: %v", err)
	}

	attacked := PackageRef{Ecosystem: "npm", Name: "republished", Version: "1.0.0", Integrity: "sha512-MALICIOUS"}
	checker := &scriptedChecker{name: "cooldown", result: CheckResult{
		Checker: "cooldown", Verdict: VerdictApprove, Reason: "would-approve",
	}}
	got := CachedRun(context.Background(), []Checker{checker}, []PackageRef{attacked}, c)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].Decision() != VerdictBlock {
		t.Errorf("republish-guard must block, got %v", got[0].Decision())
	}
	if len(got[0].Results) != 1 || got[0].Results[0].Checker != "republish-guard" {
		t.Errorf("expected republish-guard result, got %+v", got[0].Results)
	}
	if checker.callCount() != 0 {
		t.Errorf("regular checker must NOT run when republish-guard fires; calls=%d", checker.callCount())
	}
}

func TestCachedRun_FreshRun_CachesApprove(t *testing.T) {
	c := newTestCache(t)
	ref := PackageRef{Ecosystem: "npm", Name: "fresh", Version: "1.0.0", Integrity: "sha512-NEW"}
	checker := &scriptedChecker{name: "cooldown", result: CheckResult{
		Checker: "cooldown", Verdict: VerdictApprove, Reason: "fresh-pass",
	}}
	_ = CachedRun(context.Background(), []Checker{checker}, []PackageRef{ref}, c)
	if checker.callCount() != 1 {
		t.Errorf("checker should run on cache miss; calls=%d", checker.callCount())
	}
	// Second pass should hit cache.
	checker2 := &scriptedChecker{name: "cooldown", result: CheckResult{
		Checker: "cooldown", Verdict: VerdictBlock, Reason: "different",
	}}
	got := CachedRun(context.Background(), []Checker{checker2}, []PackageRef{ref}, c)
	if got[0].Decision() != VerdictApprove {
		t.Errorf("second pass must use cached approve, got %v", got[0].Decision())
	}
	if checker2.callCount() != 0 {
		t.Errorf("second-pass checker must NOT run; calls=%d", checker2.callCount())
	}
}

func TestCachedRun_FreshRun_DoesNotCacheBlock(t *testing.T) {
	c := newTestCache(t)
	ref := PackageRef{Ecosystem: "npm", Name: "blocked", Version: "1.0.0", Integrity: "sha512-B"}
	checker := &scriptedChecker{name: "cooldown", result: CheckResult{
		Checker: "cooldown", Verdict: VerdictBlock, Reason: "fresh-block",
	}}
	_ = CachedRun(context.Background(), []Checker{checker}, []PackageRef{ref}, c)
	// Block must not be cached — user fixing the issue needs fresh signal.
	if got := c.Lookup(ref); got != nil {
		t.Errorf("Block verdict should not have been cached; got %+v", got)
	}
}

func TestCachedRun_ContextCancelled_ReturnsUnknownVerdicts(t *testing.T) {
	c := newTestCache(t)
	ref := PackageRef{Ecosystem: "npm", Name: "interrupted", Version: "1.0.0"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before run
	checker := &scriptedChecker{name: "cooldown", result: CheckResult{
		Checker: "cooldown", Verdict: VerdictApprove, Reason: "ignored",
	}}
	got := CachedRun(ctx, []Checker{checker}, []PackageRef{ref}, c)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if len(got[0].Results) != 1 || got[0].Results[0].Verdict != VerdictUnknown {
		t.Errorf("cancelled context must yield Unknown verdict; got %+v", got[0].Results)
	}
}

func TestCachedRun_EmptyPackages_ReturnsNil(t *testing.T) {
	c := newTestCache(t)
	got := CachedRun(context.Background(), nil, nil, c)
	if got != nil {
		t.Errorf("empty input should return nil, got %v", got)
	}
}

func TestRun_ConcurrencyDoesntCrossWires(t *testing.T) {
	// 50 packages, the same checker — output order must match input
	// order and each package gets exactly its own result.
	refs := make([]PackageRef, 50)
	for i := range refs {
		refs[i] = PackageRef{Ecosystem: "npm", Name: namedAt(i), Version: "1.0.0"}
	}
	checker := &scriptedChecker{name: "cooldown", result: CheckResult{
		Checker: "cooldown", Verdict: VerdictApprove, Reason: "ok",
	}}
	got := Run(context.Background(), []Checker{checker}, refs)
	if len(got) != len(refs) {
		t.Fatalf("len mismatch: got %d, want %d", len(got), len(refs))
	}
	for i, pc := range got {
		if pc.Package.Name != refs[i].Name {
			t.Errorf("index %d: got %q, want %q", i, pc.Package.Name, refs[i].Name)
		}
	}
}

func TestRun_HonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	checker := &scriptedChecker{name: "cooldown", result: CheckResult{
		Checker: "cooldown", Verdict: VerdictApprove, Reason: "ignored",
	}}
	got := Run(ctx, []Checker{checker}, []PackageRef{{Ecosystem: "npm", Name: "x", Version: "1"}})
	if len(got) != 1 || got[0].Results[0].Verdict != VerdictUnknown {
		t.Errorf("cancelled context must yield Unknown; got %+v", got)
	}
}

func TestSummarize_CountsByVerdict(t *testing.T) {
	checks := []PackageCheck{
		{Results: []CheckResult{{Verdict: VerdictApprove}}},
		{Results: []CheckResult{{Verdict: VerdictApprove}}},
		{Results: []CheckResult{{Verdict: VerdictWarn}}},
		{Results: []CheckResult{{Verdict: VerdictBlock}}},
		{Results: []CheckResult{{Verdict: VerdictUnknown}}},
	}
	s := Summarize(checks)
	// Order matters in the user-facing string: approve, warn, block, unknown
	want := "approve=2 warn=1 block=1 unknown=1"
	if s != want {
		t.Errorf("got %q, want %q", s, want)
	}
}

func TestSummarize_OmitsZeroes(t *testing.T) {
	checks := []PackageCheck{
		{Results: []CheckResult{{Verdict: VerdictApprove}}},
		{Results: []CheckResult{{Verdict: VerdictApprove}}},
	}
	s := Summarize(checks)
	if s != "approve=2" {
		t.Errorf("zeroes should be omitted; got %q", s)
	}
}

func TestSortByVerdict_WorstFirst_TiesBrokenByName(t *testing.T) {
	checks := []PackageCheck{
		{Package: PackageRef{Ecosystem: "npm", Name: "z", Version: "1"}, Results: []CheckResult{{Verdict: VerdictApprove}}},
		{Package: PackageRef{Ecosystem: "npm", Name: "a", Version: "1"}, Results: []CheckResult{{Verdict: VerdictBlock}}},
		{Package: PackageRef{Ecosystem: "npm", Name: "b", Version: "1"}, Results: []CheckResult{{Verdict: VerdictWarn}}},
		{Package: PackageRef{Ecosystem: "npm", Name: "c", Version: "1"}, Results: []CheckResult{{Verdict: VerdictApprove}}},
	}
	SortByVerdict(checks)
	wantOrder := []string{"a", "b", "c", "z"}
	for i, pc := range checks {
		if pc.Package.Name != wantOrder[i] {
			t.Errorf("position %d: got %q, want %q (full: %v)", i, pc.Package.Name, wantOrder[i], namesOf(checks))
		}
	}
}

func TestPackageCheck_Blocked_FiltersToBlocks(t *testing.T) {
	pc := PackageCheck{Results: []CheckResult{
		{Checker: "a", Verdict: VerdictApprove},
		{Checker: "b", Verdict: VerdictBlock, Reason: "first block"},
		{Checker: "c", Verdict: VerdictWarn},
		{Checker: "d", Verdict: VerdictBlock, Reason: "second block"},
	}}
	got := pc.Blocked()
	if len(got) != 2 || got[0].Checker != "b" || got[1].Checker != "d" {
		t.Errorf("Blocked() filter wrong: %+v", got)
	}
}

func TestPackageCheck_Warnings_FiltersToWarns(t *testing.T) {
	pc := PackageCheck{Results: []CheckResult{
		{Checker: "a", Verdict: VerdictApprove},
		{Checker: "b", Verdict: VerdictWarn, Reason: "w1"},
		{Checker: "c", Verdict: VerdictBlock},
		{Checker: "d", Verdict: VerdictWarn, Reason: "w2"},
	}}
	got := pc.Warnings()
	if len(got) != 2 || got[0].Checker != "b" || got[1].Checker != "d" {
		t.Errorf("Warnings() filter wrong: %+v", got)
	}
}

func TestVerdict_String_AllVariants(t *testing.T) {
	cases := map[Verdict]string{
		VerdictApprove: "approve",
		VerdictWarn:    "warn",
		VerdictBlock:   "block",
		VerdictUnknown: "unknown",
		Verdict(99):    "unknown", // unrecognized falls through
	}
	for v, want := range cases {
		if v.String() != want {
			t.Errorf("Verdict(%d).String() = %q, want %q", int(v), v.String(), want)
		}
	}
}

// Test fixtures.

func namedAt(i int) string {
	if i < 10 {
		return string(rune('a'+i)) + "-pkg"
	}
	return "pkg-" + string(rune('a'+i%26))
}

func namesOf(checks []PackageCheck) []string {
	out := make([]string, len(checks))
	for i, c := range checks {
		out[i] = c.Package.Name
	}
	return out
}
