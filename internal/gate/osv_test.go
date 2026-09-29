package gate

import (
	"context"
	"errors"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/osv"
)

type stubOSV struct {
	results []osv.QueryResult
	err     error
}

func (s stubOSV) QueryBatch(context.Context, []osv.Query) ([]osv.QueryResult, error) {
	return s.results, s.err
}

func TestOSV_ApprovesCleanPackage(t *testing.T) {
	o := &OSVCheck{Client: stubOSV{results: []osv.QueryResult{{}}}} // no Vulns
	r := o.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})
	if r.Verdict != VerdictApprove {
		t.Errorf("clean package should Approve, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestOSV_BlocksOnMALMatch(t *testing.T) {
	o := &OSVCheck{Client: stubOSV{results: []osv.QueryResult{
		{Vulns: []osv.VulnRef{{ID: "MAL-2025-0001"}}},
	}}}
	r := o.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "shai-hulud-payload", Version: "1.0.0"})
	if r.Verdict != VerdictBlock {
		t.Errorf("MAL-* match should Block, got %v: %q", r.Verdict, r.Reason)
	}
	if !contains(r.Reason, "MAL-2025-0001") {
		t.Errorf("reason should name the MAL-* id, got %q", r.Reason)
	}
}

func TestOSV_WarnsOnCVEButNotBlock(t *testing.T) {
	o := &OSVCheck{Client: stubOSV{results: []osv.QueryResult{
		{Vulns: []osv.VulnRef{{ID: "GHSA-29mw-wpgm-hmr9"}, {ID: "CVE-2021-23337"}}},
	}}}
	r := o.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"})
	if r.Verdict != VerdictWarn {
		t.Errorf("CVE-only match should Warn (not Block), got %v: %q", r.Verdict, r.Reason)
	}
}

func TestOSV_PrioritizesMALOverCVE(t *testing.T) {
	o := &OSVCheck{Client: stubOSV{results: []osv.QueryResult{
		{Vulns: []osv.VulnRef{{ID: "MAL-2025-0007"}, {ID: "GHSA-xx-yy-zz"}}},
	}}}
	r := o.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if r.Verdict != VerdictBlock {
		t.Errorf("mixed MAL+CVE should Block, got %v", r.Verdict)
	}
	if !contains(r.Detail, "GHSA-xx-yy-zz") {
		t.Errorf("Detail should still surface CVE-side matches, got %q", r.Detail)
	}
}

func TestOSV_UnknownOnNetworkError(t *testing.T) {
	o := &OSVCheck{Client: stubOSV{err: errors.New("connection refused")}}
	r := o.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("network error should Unknown, got %v", r.Verdict)
	}
}

func TestOSV_UnknownEcosystem(t *testing.T) {
	o := &OSVCheck{Client: stubOSV{}}
	r := o.Check(context.Background(), PackageRef{Ecosystem: "homebrew", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("ecosystem OSV doesn't catalog should Unknown, got %v", r.Verdict)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
