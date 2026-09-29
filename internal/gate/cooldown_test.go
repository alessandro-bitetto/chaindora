package gate

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCooldown_BlocksFreshVersion(t *testing.T) {
	c := &Cooldown{
		Threshold: 72 * time.Hour,
		Probes: probesWith("npm", stubProbe{
			publishedAtByVersion: map[string]time.Time{"0.0.1": time.Now().Add(-14 * time.Minute)},
		}),
	}
	r := c.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "evil", Version: "0.0.1"})
	if r.Verdict != VerdictBlock {
		t.Errorf("fresh version should Block, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestCooldown_ApprovesAgedVersion(t *testing.T) {
	c := &Cooldown{
		Threshold: 72 * time.Hour,
		Probes: probesWith("npm", stubProbe{
			publishedAtByVersion: map[string]time.Time{"4.17.21": time.Now().AddDate(0, -1, 0)},
		}),
	}
	r := c.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})
	if r.Verdict != VerdictApprove {
		t.Errorf("month-old version should Approve, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestCooldown_UnknownOnNetworkError(t *testing.T) {
	c := &Cooldown{
		Threshold: 72 * time.Hour,
		Probes: probesWith("npm", stubProbe{
			publishedAtErr: errors.New("connection refused"),
		}),
	}
	r := c.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("network error should Unknown, got %v", r.Verdict)
	}
}

func TestCooldown_UnknownOnZeroPublishDate(t *testing.T) {
	c := &Cooldown{
		Threshold: 72 * time.Hour,
		Probes:    probesWith("npm", stubProbe{}),
	}
	r := c.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("zero publish date should Unknown, got %v", r.Verdict)
	}
}

func TestCooldown_UnknownEcosystemReturnsUnknown(t *testing.T) {
	c := &Cooldown{Threshold: time.Hour, Probes: NewProbes()}
	r := c.Check(context.Background(), PackageRef{Ecosystem: "homebrew", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("unsupported ecosystem should Unknown, got %v", r.Verdict)
	}
}

func TestCooldown_PyPIEcosystemViaCanonicalAlias(t *testing.T) {
	// "pip" should canonicalize to "pypi" so users can use
	// either ecosystem string.
	c := &Cooldown{
		Threshold: 72 * time.Hour,
		Probes: probesWith("pypi", stubProbe{
			publishedAtByVersion: map[string]time.Time{"2.32.0": time.Now().AddDate(0, -3, 0)},
		}),
	}
	r := c.Check(context.Background(), PackageRef{Ecosystem: "pip", Name: "requests", Version: "2.32.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("pip alias should resolve to pypi probe: got %v: %q", r.Verdict, r.Reason)
	}
}

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{42 * time.Second, "42s"},
		{14 * time.Minute, "14m"},
		{3 * time.Hour, "3h"},
		{3*time.Hour + 22*time.Minute, "3h 22m"},
		{29 * 24 * time.Hour, "29d"},
		{29*24*time.Hour + 5*time.Hour, "29d 5h"},
	}
	for _, c := range cases {
		if got := humanDuration(c.d); got != c.want {
			t.Errorf("humanDuration(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}
