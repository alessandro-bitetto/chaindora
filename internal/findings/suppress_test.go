package findings

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadSuppressions_ReadsValidFile(t *testing.T) {
	tmp := t.TempDir()
	body := `suppress:
  - vuln_id: GHSA-xxxx
    package: lodash
    reason: "Known false positive in our use case"
    expires: 2026-12-31
  - fingerprint: abc123
    reason: "Tracked in JIRA-555"
`
	if err := os.WriteFile(filepath.Join(tmp, ".chaindora-ignore.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	supp, err := LoadSuppressions(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if supp == nil {
		t.Fatal("expected suppressions, got nil")
	}
	if len(supp.Suppress) != 2 {
		t.Errorf("got %d entries, want 2", len(supp.Suppress))
	}
}

func TestLoadSuppressions_NoFileReturnsNil(t *testing.T) {
	supp, err := LoadSuppressions(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if supp != nil {
		t.Errorf("expected nil for missing file, got %v", supp)
	}
}

func TestLoadSuppressions_RejectsMissingReason(t *testing.T) {
	tmp := t.TempDir()
	body := `suppress:
  - vuln_id: GHSA-xxxx
    package: lodash
`
	if err := os.WriteFile(filepath.Join(tmp, ".chaindora-ignore.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadSuppressions(tmp)
	if err == nil {
		t.Errorf("expected error on missing reason")
	}
}

func TestLoadSuppressions_RejectsEmptyMatcher(t *testing.T) {
	tmp := t.TempDir()
	body := `suppress:
  - reason: "Cosmic"
`
	if err := os.WriteFile(filepath.Join(tmp, ".chaindora-ignore.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadSuppressions(tmp)
	if err == nil {
		t.Errorf("expected error on missing matcher")
	}
}

func TestSuppression_Matches(t *testing.T) {
	f := Finding{VulnID: "GHSA-xxx", Name: "lodash", Version: "4.17.20"}
	cases := []struct {
		name string
		s    Suppression
		want bool
	}{
		{"fingerprint matches", Suppression{Fingerprint: Fingerprint(f)}, true},
		{"fingerprint mismatches", Suppression{Fingerprint: "nope"}, false},
		{"vuln_id alone matches", Suppression{VulnID: "GHSA-xxx"}, true},
		{"vuln_id + package matches", Suppression{VulnID: "GHSA-xxx", Package: "lodash"}, true},
		{"vuln_id + wrong package", Suppression{VulnID: "GHSA-xxx", Package: "react"}, false},
		{"vuln_id + version matches", Suppression{VulnID: "GHSA-xxx", Version: "4.17.20"}, true},
		{"vuln_id + wrong version", Suppression{VulnID: "GHSA-xxx", Version: "4.17.99"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.s.Reason = "x" // ensure matcher logic alone is tested
			if got := c.s.Matches(f); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestFilterSuppressed_SplitsKeptVsSuppressed(t *testing.T) {
	fs := []Finding{
		{VulnID: "A", Name: "x"},
		{VulnID: "B", Name: "y"},
		{VulnID: "C", Name: "z"},
	}
	supp := &Suppressions{Suppress: []Suppression{
		{VulnID: "B", Reason: "ok"},
	}}
	kept, suppressed := FilterSuppressed(fs, supp, time.Now())
	if len(kept) != 2 || len(suppressed) != 1 {
		t.Errorf("kept=%d suppressed=%d, want 2/1", len(kept), len(suppressed))
	}
	if suppressed[0].Finding.VulnID != "B" {
		t.Errorf("wrong finding suppressed: %v", suppressed[0])
	}
}

func TestSuppression_Expired(t *testing.T) {
	past := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	future := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)

	if !(Suppression{Expires: past.Format("2006-01-02")}).Expired(now) {
		t.Errorf("past date should be expired")
	}
	if (Suppression{Expires: future.Format("2006-01-02")}).Expired(now) {
		t.Errorf("future date should NOT be expired")
	}
	if (Suppression{Expires: ""}).Expired(now) {
		t.Errorf("empty expires should never be expired")
	}
}

func TestFilterSuppressed_NilSuppressionsPassthrough(t *testing.T) {
	fs := []Finding{{VulnID: "A"}, {VulnID: "B"}}
	kept, supp := FilterSuppressed(fs, nil, time.Now())
	if len(kept) != 2 || len(supp) != 0 {
		t.Errorf("nil suppressions should pass everything through; got kept=%d supp=%d", len(kept), len(supp))
	}
}
