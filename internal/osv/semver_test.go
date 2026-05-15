package osv

import "testing"

func TestParseSemver(t *testing.T) {
	cases := []struct {
		in    string
		ok    bool
		major int
	}{
		{"1.2.3", true, 1},
		{"v6.4.2", true, 6},
		{"4.2.5", true, 4},
		{"1.0.0-rc.1", true, 1},
		{"1.2.3+build.1", true, 1},
		{"5", true, 5},
		{"5.4", true, 5},
		{"not-a-version", false, 0},
		{"", false, 0},
	}
	for _, c := range cases {
		got, ok := parseSemver(c.in)
		if ok != c.ok {
			t.Errorf("parseSemver(%q) ok=%v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && got.Major != c.major {
			t.Errorf("parseSemver(%q) major=%d, want %d", c.in, got.Major, c.major)
		}
	}
}

func TestSemverComparison(t *testing.T) {
	cases := []struct {
		a, b string
		aLT  bool
	}{
		{"1.0.0", "2.0.0", true},
		{"1.2.3", "1.2.4", true},
		{"1.0.0-rc.1", "1.0.0", true},
		{"2.0.0", "1.99.99", false},
		{"6.3.5", "6.4.2", true},
		{"6.4.2", "6.3.5", false},
	}
	for _, c := range cases {
		a, _ := parseSemver(c.a)
		b, _ := parseSemver(c.b)
		if got := a.LessThan(b); got != c.aLT {
			t.Errorf("%q < %q = %v, want %v", c.a, c.b, got, c.aLT)
		}
	}
}

func TestMinFixedInMajor(t *testing.T) {
	// The real-world case from the v0.7.1 audit:
	// vite 6.3.5 is vulnerable; OSV says fixed in 6.4.2 (same major) AND
	// 8.0.0 (major bump). We should pick 6.4.2, not 8.0.0.
	v := &Vulnerability{
		Affected: []Affected{
			{
				Package: AffectedPackage{Name: "vite", Ecosystem: "npm"},
				Ranges: []Range{
					{
						Type: "SEMVER",
						Events: []Event{
							{Introduced: "0"},
							{Fixed: "6.4.2"},
						},
					},
					{
						Type: "SEMVER",
						Events: []Event{
							{Introduced: "7.0.0"},
							{Fixed: "8.0.0"},
						},
					},
				},
			},
		},
	}
	got := MinFixedInMajor(v, "npm", "6.3.5")
	if got != "6.4.2" {
		t.Errorf("MinFixedInMajor: got %q, want 6.4.2", got)
	}
}

func TestMinFixedInMajor_NoInMajorFix(t *testing.T) {
	// Only fix requires major bump: return "" so the caller can mark
	// the plan FixManual.
	v := &Vulnerability{
		Affected: []Affected{
			{
				Package: AffectedPackage{Name: "old-pkg", Ecosystem: "npm"},
				Ranges: []Range{
					{
						Type: "SEMVER",
						Events: []Event{
							{Introduced: "0"},
							{Fixed: "2.0.0"},
						},
					},
				},
			},
		},
	}
	if got := MinFixedInMajor(v, "npm", "1.5.0"); got != "" {
		t.Errorf("expected no in-major fix, got %q", got)
	}
}

func TestMinFixedInMajor_PicksSmallest(t *testing.T) {
	// Multiple in-major fixes. We want the smallest.
	v := &Vulnerability{
		Affected: []Affected{
			{
				Package: AffectedPackage{Name: "x", Ecosystem: "npm"},
				Ranges: []Range{
					{Type: "SEMVER", Events: []Event{{Fixed: "1.10.0"}}},
					{Type: "SEMVER", Events: []Event{{Fixed: "1.5.3"}}},
					{Type: "SEMVER", Events: []Event{{Fixed: "1.7.2"}}},
				},
			},
		},
	}
	if got := MinFixedInMajor(v, "npm", "1.2.0"); got != "1.5.3" {
		t.Errorf("expected smallest in-major fix 1.5.3, got %q", got)
	}
}

func TestMinFixedInMajor_EcosystemFilter(t *testing.T) {
	v := &Vulnerability{
		Affected: []Affected{
			{
				Package: AffectedPackage{Name: "foo", Ecosystem: "PyPI"},
				Ranges:  []Range{{Type: "SEMVER", Events: []Event{{Fixed: "1.2.3"}}}},
			},
			{
				Package: AffectedPackage{Name: "foo", Ecosystem: "npm"},
				Ranges:  []Range{{Type: "SEMVER", Events: []Event{{Fixed: "1.5.0"}}}},
			},
		},
	}
	if got := MinFixedInMajor(v, "npm", "1.0.0"); got != "1.5.0" {
		t.Errorf("ecosystem-filtered result: got %q", got)
	}
	if got := MinFixedInMajor(v, "PyPI", "1.0.0"); got != "1.2.3" {
		t.Errorf("ecosystem-filtered result: got %q", got)
	}
}

func TestMinFixedInMajor_UnparseableCurrent(t *testing.T) {
	v := &Vulnerability{
		Affected: []Affected{
			{
				Package: AffectedPackage{Name: "x", Ecosystem: "npm"},
				Ranges:  []Range{{Type: "SEMVER", Events: []Event{{Fixed: "1.2.3"}}}},
			},
		},
	}
	// Non-SemVer current version (PEP 440 style) — return "" so the
	// caller falls back to a manual plan instead of guessing.
	if got := MinFixedInMajor(v, "npm", "1.2.3a1"); got != "" {
		t.Errorf("unparseable current version should yield '', got %q", got)
	}
}
