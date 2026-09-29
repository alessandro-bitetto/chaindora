package gate

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"
)

func TestPolicyEvaluatesMixedResultsIndependently(t *testing.T) {
	for _, order := range [][]Verdict{{VerdictUnknown, VerdictWarn}, {VerdictWarn, VerdictUnknown}} {
		for _, tc := range []struct {
			name    string
			policy  Policy
			allow   bool
			verdict Verdict
		}{
			{"strict", Strict(), false, VerdictUnknown},
			{"lenient still fails closed", Lenient(), false, VerdictUnknown},
			{"offline still rejects warnings", Policy{AllowOnUnknown: true}, false, VerdictWarn},
			{"both overrides", Policy{AllowOnWarn: true, AllowOnUnknown: true}, true, VerdictWarn},
		} {
			t.Run(tc.name, func(t *testing.T) {
				pc := PackageCheck{Results: []CheckResult{{Verdict: order[0]}, {Verdict: order[1]}}}
				allow, verdict := tc.policy.Decide(pc)
				if allow != tc.allow || verdict != tc.verdict {
					t.Fatalf("Decide(%v) = %v, %v; want %v, %v", order, allow, verdict, tc.allow, tc.verdict)
				}
				pc.Results = append(pc.Results, CheckResult{Verdict: VerdictBlock})
				if allow, verdict := tc.policy.Decide(pc); allow || verdict != VerdictBlock {
					t.Fatal("explicit block must win even with both overrides")
				}
			})
		}
	}
	if allow, _ := Lenient().Decide(PackageCheck{}); allow {
		t.Fatal("no checker evidence must not approve under lenient policy")
	}
}

func TestCachedRunScanCannotBypassStrongerGate(t *testing.T) {
	c := newTestCache(t)
	ref := PackageRef{Ecosystem: "npm", Name: "example", Version: "1", Integrity: "sha512-A"}
	CachedRun(context.Background(), []Checker{fakeChecker{name: "cooldown", result: CheckResult{
		Checker: "cooldown", Verdict: VerdictApprove,
	}}}, []PackageRef{ref}, c)
	for _, name := range []string{"osv-malicious", "allowlist", "provenance", "static-pattern"} {
		checker := &scriptedChecker{name: name, result: CheckResult{Checker: name, Verdict: VerdictBlock}}
		got := CachedRun(context.Background(), []Checker{checker}, []PackageRef{ref}, c)
		if got[0].Decision() != VerdictBlock || checker.callCount() != 1 {
			t.Fatalf("cached partial stack bypassed %s: %+v", name, got)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := CachedRun(ctx, []Checker{fakeChecker{name: "osv-malicious"}}, []PackageRef{ref}, c)
	if got[0].Decision() != VerdictUnknown {
		t.Fatal("cached approval masked cancellation")
	}
}

func TestRepublishHistorySurvivesApprovalTTL(t *testing.T) {
	c := newTestCache(t)
	ref := PackageRef{Ecosystem: "npm", Name: "old", Version: "1", Integrity: "sha512-OLD"}
	if err := c.Store(ref, approvedCheck("cooldown")); err != nil {
		t.Fatal(err)
	}
	entry := c.Lookup(ref)
	entry.CachedAt = time.Now().Add(-30 * 24 * time.Hour)
	data, _ := json.Marshal(entry)
	if err := os.WriteFile(c.entryPath(ref), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if c.Lookup(ref) != nil {
		t.Fatal("expired approval should miss")
	}
	ref.Integrity = "sha512-NEW"
	got := CachedRun(context.Background(), nil, []PackageRef{ref}, c)
	if got[0].Decision() != VerdictBlock {
		t.Fatal("expiration erased republish evidence")
	}
}

func TestCacheConcurrentStoresRemainReadable(t *testing.T) {
	c := newTestCache(t)
	ref := PackageRef{Ecosystem: "npm", Name: "duplicate", Version: "1", Integrity: "sha512-A"}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Store(ref, approvedCheck("cooldown")); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if c.Lookup(ref) == nil {
		t.Fatal("concurrent stores corrupted history")
	}
}
