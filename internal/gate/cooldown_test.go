package gate

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stubNPM struct {
	publishedAt time.Time
	err         error
}

func (s stubNPM) PublishedAtVersion(context.Context, string, string) (time.Time, error) {
	return s.publishedAt, s.err
}

func TestCooldown_BlocksFreshVersion(t *testing.T) {
	c := &Cooldown{
		Threshold: 72 * time.Hour,
		NPM:       stubNPM{publishedAt: time.Now().Add(-14 * time.Minute)},
	}
	r := c.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "evil", Version: "0.0.1"})
	if r.Verdict != VerdictBlock {
		t.Errorf("fresh version should Block, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestCooldown_ApprovesAgedVersion(t *testing.T) {
	c := &Cooldown{
		Threshold: 72 * time.Hour,
		NPM:       stubNPM{publishedAt: time.Now().AddDate(0, -1, 0)},
	}
	r := c.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})
	if r.Verdict != VerdictApprove {
		t.Errorf("month-old version should Approve, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestCooldown_UnknownOnNetworkError(t *testing.T) {
	c := &Cooldown{
		Threshold: 72 * time.Hour,
		NPM:       stubNPM{err: errors.New("connection refused")},
	}
	r := c.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("network error should Unknown (fail-closed policy converts to block), got %v", r.Verdict)
	}
}

func TestCooldown_UnknownOnZeroPublishDate(t *testing.T) {
	c := &Cooldown{
		Threshold: 72 * time.Hour,
		NPM:       stubNPM{}, // zero time
	}
	r := c.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("zero publish date should Unknown, got %v", r.Verdict)
	}
}

func TestCooldown_UnknownEcosystemReturnsUnknown(t *testing.T) {
	c := &Cooldown{Threshold: time.Hour, NPM: stubNPM{}}
	r := c.Check(context.Background(), PackageRef{Ecosystem: "homebrew", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("unsupported ecosystem should Unknown, got %v", r.Verdict)
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
