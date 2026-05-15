package findings

import "testing"

// TestDedupePackage_CollapsesMultipleCVEsOnSamePackage exercises the
// v0.8.1 motivating case: lodash 4.17.20 has 5 CVEs, each producing a
// fix plan pinned to a different `^X.Y.Z` (4.17.21 / 4.18.0 / etc.).
// The package-level dedup must collapse them to ONE plan pinned to
// the max (4.18.0) and accumulate every CVE ID in CoveredVulnIDs.
func TestDedupePackage_CollapsesMultipleCVEsOnSamePackage(t *testing.T) {
	plans := []FixPlan{
		{
			VulnID: "CVE-A", Severity: SeverityMedium, Category: FixSemiSafe,
			Command:         "cd /p && npm install lodash@^4.17.21",
			ProjectDir:      "/p", PackageName: "lodash", RequiredVersion: "4.17.21",
		},
		{
			VulnID: "CVE-B", Severity: SeverityHigh, Category: FixSemiSafe,
			Command:         "cd /p && npm install lodash@^4.18.0",
			ProjectDir:      "/p", PackageName: "lodash", RequiredVersion: "4.18.0",
		},
		{
			VulnID: "CVE-C", Severity: SeverityLow, Category: FixSemiSafe,
			Command:         "cd /p && npm install lodash@^4.17.21",
			ProjectDir:      "/p", PackageName: "lodash", RequiredVersion: "4.17.21",
		},
	}
	out := DedupePlans(plans)
	if len(out) != 1 {
		t.Fatalf("expected 1 deduped plan, got %d: %+v", len(out), out)
	}
	if out[0].RequiredVersion != "4.18.0" {
		t.Errorf("dedup should pick max required version, got %q", out[0].RequiredVersion)
	}
	if out[0].Severity != SeverityHigh {
		t.Errorf("dedup should promote highest severity, got %q", out[0].Severity)
	}
	if got := len(out[0].CoveredVulnIDs); got != 3 {
		t.Errorf("CoveredVulnIDs should include all 3 CVEs, got %d: %v", got, out[0].CoveredVulnIDs)
	}
}

// TestDedupePackage_PreservesDifferentPackages confirms we group on
// (ProjectDir, PackageName) — not just project, not just package.
func TestDedupePackage_PreservesDifferentPackages(t *testing.T) {
	plans := []FixPlan{
		{VulnID: "X", ProjectDir: "/p", PackageName: "lodash", RequiredVersion: "4.17.21", Command: "a"},
		{VulnID: "Y", ProjectDir: "/p", PackageName: "react", RequiredVersion: "18.2.0", Command: "b"},
		{VulnID: "Z", ProjectDir: "/q", PackageName: "lodash", RequiredVersion: "4.17.21", Command: "c"},
	}
	out := DedupePlans(plans)
	if len(out) != 3 {
		t.Fatalf("expected 3 plans (different packages or projects), got %d", len(out))
	}
}

// TestDedupePackage_PassThroughForMissingKeys verifies plans without
// the dedup keys (incident-pack uninstalls, hostforensics manuals,
// global-package fixes) flow through untouched — only the
// command-level dedup applies to them.
func TestDedupePackage_PassThroughForMissingKeys(t *testing.T) {
	plans := []FixPlan{
		{VulnID: "X", Command: "rm -f /tmp/worm.js", Category: FixSafe},
		{VulnID: "Y", Command: "rm -f /tmp/worm.js", Category: FixSafe}, // identical command — command-dedup collapses
		{VulnID: "Z", Command: "npm install -g pkg@latest", Category: FixSafe},
	}
	out := DedupePlans(plans)
	if len(out) != 2 {
		t.Fatalf("expected 2 (identical commands collapsed, third unique), got %d: %v", len(out), out)
	}
}

func TestDedupePackage_IdempotentOnSecondRun(t *testing.T) {
	plans := []FixPlan{
		{VulnID: "A", ProjectDir: "/p", PackageName: "x", RequiredVersion: "1.0.0", Command: "cmd1"},
		{VulnID: "B", ProjectDir: "/p", PackageName: "x", RequiredVersion: "1.1.0", Command: "cmd2"},
	}
	first := DedupePlans(plans)
	second := DedupePlans(first)
	if len(first) != 1 || len(second) != 1 {
		t.Errorf("expected idempotent collapse to 1, got first=%d second=%d", len(first), len(second))
	}
	if first[0].RequiredVersion != second[0].RequiredVersion {
		t.Errorf("idempotent dedup changed RequiredVersion: %q vs %q", first[0].RequiredVersion, second[0].RequiredVersion)
	}
}

func TestCompareRequired(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"4.17.20", "4.17.21", -1},
		{"4.17.21", "4.17.20", 1},
		{"4.18.0", "4.17.21", 1},
		{"v4.18.0", "4.18.0", 0},
		{"4.18.0-rc.1", "4.18.0", 0}, // prerelease stripped — good enough for "which pin wins"
		{"5.0.0", "4.99.99", 1},
		{"weird", "1.0.0", 1}, // fallback to lex; "weird" > "1.0.0" — production correctness doesn't depend on this, just don't crash
	}
	for _, c := range cases {
		if got := compareRequired(c.a, c.b); got != c.want {
			t.Errorf("compareRequired(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
