package osv

import (
	"math"
	"testing"
)

func TestParseCVSSv3(t *testing.T) {
	cases := []struct {
		name   string
		vector string
		want   float64
		wantOk bool
	}{
		{
			name:   "max base unchanged scope",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			want:   9.8,
			wantOk: true,
		},
		{
			name:   "max with scope change saturates to 10",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			want:   10.0,
			wantOk: true,
		},
		{
			// lodash CVE-2021-23337: AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H → 7.2
			name:   "lodash cmd injection",
			vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
			want:   7.2,
			wantOk: true,
		},
		{
			// All CIA None → 0
			name:   "zero impact",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			want:   0,
			wantOk: true,
		},
		{
			name:   "rejects non-v3 prefix",
			vector: "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:N",
			wantOk: false,
		},
		{
			name:   "rejects missing AC",
			vector: "CVSS:3.1/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantOk: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseCVSSv3(c.vector)
			if ok != c.wantOk {
				t.Fatalf("ok = %v, want %v (score=%v)", ok, c.wantOk, got)
			}
			if c.wantOk && math.Abs(got-c.want) > 0.1 {
				t.Errorf("score = %v, want %v", got, c.want)
			}
		})
	}
}

func TestSeverityLevel(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0, "NONE"},
		{0.1, "LOW"},
		{3.9, "LOW"},
		{4.0, "MEDIUM"},
		{6.9, "MEDIUM"},
		{7.0, "HIGH"},
		{8.9, "HIGH"},
		{9.0, "CRITICAL"},
		{10.0, "CRITICAL"},
	}
	for _, c := range cases {
		if got := SeverityLevel(c.score); got != c.want {
			t.Errorf("SeverityLevel(%v) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestHighestSeverityFromVulns(t *testing.T) {
	sevs := []Severity{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}, // LOW
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, // CRITICAL
		{Type: "CVSS_V3", Score: ""},                                              // skipped
	}
	if got := HighestSeverityFromVulns(sevs); got != "CRITICAL" {
		t.Errorf("got %q, want CRITICAL", got)
	}
	if got := HighestSeverityFromVulns(nil); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}
