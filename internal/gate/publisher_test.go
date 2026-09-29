package gate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

func TestPublisherChange_ApprovesSamePublisher(t *testing.T) {
	versions := []registries.VersionInfo{
		{Version: "1.0.0", Publisher: "alice", PublishedAt: time.Now().Add(-30 * 24 * time.Hour)},
		{Version: "1.0.1", Publisher: "alice", PublishedAt: time.Now().Add(-7 * 24 * time.Hour)},
	}
	p := &PublisherChange{
		Probes: probesWith("npm", stubProbe{
			publisherByVersion: map[string]string{"1.0.0": "alice", "1.0.1": "alice"},
			versions:           versions,
		}),
	}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "pkg", Version: "1.0.1"})
	if r.Verdict != VerdictApprove {
		t.Errorf("same publisher should Approve, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestPublisherChange_WarnsOnChange(t *testing.T) {
	versions := []registries.VersionInfo{
		{Version: "1.0.0", Publisher: "alice", PublishedAt: time.Now().Add(-30 * 24 * time.Hour)},
		{Version: "1.0.1", Publisher: "bob", PublishedAt: time.Now().Add(-7 * 24 * time.Hour)},
	}
	p := &PublisherChange{
		Probes: probesWith("npm", stubProbe{
			publisherByVersion: map[string]string{"1.0.0": "alice", "1.0.1": "bob"},
			versions:           versions,
		}),
	}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "pkg", Version: "1.0.1"})
	if r.Verdict != VerdictWarn {
		t.Errorf("publisher change should Warn, got %v: %q", r.Verdict, r.Reason)
	}
}

// A change to a trusted-publishing identity ("GitHub Actions") backed by
// sigstore provenance is a benign migration to OIDC trusted publishing,
// not a takeover — Babel/eslint/semver et al. all did this.
func TestPublisherChange_TrustedPublishingMigrationApproves(t *testing.T) {
	versions := []registries.VersionInfo{
		{Version: "1.0.0", Publisher: "alice", PublishedAt: time.Now().Add(-30 * 24 * time.Hour)},
		{Version: "1.0.1", Publisher: "GitHub Actions", PublishedAt: time.Now().Add(-7 * 24 * time.Hour)},
	}
	probes := NewProbes()
	probes.Register("npm", stubProbe{
		publisherByVersion: map[string]string{"1.0.0": "alice", "1.0.1": "GitHub Actions"},
		versions:           versions,
	})
	probes.RegisterProvenance("npm", stubProvenance{hasProv: true})
	p := &PublisherChange{Probes: probes}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "pkg", Version: "1.0.1"})
	if r.Verdict != VerdictApprove {
		t.Errorf("trusted-publishing migration (GitHub Actions + provenance) should Approve, got %v: %q", r.Verdict, r.Reason)
	}
}

// The trusted-publishing name alone is not enough — without provenance to
// back it, a change to "GitHub Actions" still Warns (can't be spoofed).
func TestPublisherChange_CIIdentityWithoutProvenanceStillWarns(t *testing.T) {
	versions := []registries.VersionInfo{
		{Version: "1.0.0", Publisher: "alice", PublishedAt: time.Now().Add(-30 * 24 * time.Hour)},
		{Version: "1.0.1", Publisher: "GitHub Actions", PublishedAt: time.Now().Add(-7 * 24 * time.Hour)},
	}
	probes := NewProbes()
	probes.Register("npm", stubProbe{
		publisherByVersion: map[string]string{"1.0.0": "alice", "1.0.1": "GitHub Actions"},
		versions:           versions,
	})
	probes.RegisterProvenance("npm", stubProvenance{hasProv: false})
	p := &PublisherChange{Probes: probes}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "pkg", Version: "1.0.1"})
	if r.Verdict != VerdictWarn {
		t.Errorf("CI identity without provenance should still Warn, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestPublisherChange_WarnsOnFirstPublish(t *testing.T) {
	versions := []registries.VersionInfo{
		{Version: "0.1.0", Publisher: "alice", PublishedAt: time.Now()},
	}
	p := &PublisherChange{
		Probes: probesWith("npm", stubProbe{
			publisherByVersion: map[string]string{"0.1.0": "alice"},
			versions:           versions,
		}),
	}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "pkg", Version: "0.1.0"})
	if r.Verdict != VerdictWarn {
		t.Errorf("first publish should Warn (brand-new signal), got %v", r.Verdict)
	}
}

func TestPublisherChange_UnknownOnNetworkError(t *testing.T) {
	p := &PublisherChange{Probes: probesWith("npm", stubProbe{publisherErr: errors.New("dns failure")})}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("network error should Unknown, got %v", r.Verdict)
	}
}

func TestPublisherChange_UnknownWhenCurrentPublisherMissing(t *testing.T) {
	p := &PublisherChange{Probes: probesWith("npm", stubProbe{
		publisherByVersion: map[string]string{"1.0.0": ""},
		versions:           []registries.VersionInfo{{Version: "1.0.0", Publisher: ""}},
	})}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("missing publisher should Unknown, got %v", r.Verdict)
	}
}

func TestPublisherChange_UnregisteredEcosystemPassthrough(t *testing.T) {
	p := &PublisherChange{Probes: NewProbes()}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "exotic", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("unregistered ecosystem should Approve (passthrough), got %v", r.Verdict)
	}
}

func TestPriorVersion(t *testing.T) {
	versions := []registries.VersionInfo{
		{Version: "1.0.0"},
		{Version: "1.0.1"},
		{Version: "1.0.2"},
	}
	if got := priorVersion(versions, "1.0.0"); got != nil {
		t.Errorf("first version should have no prior, got %v", got)
	}
	if got := priorVersion(versions, "1.0.1"); got == nil || got.Version != "1.0.0" {
		t.Errorf("prior of 1.0.1 should be 1.0.0, got %v", got)
	}
	if got := priorVersion(versions, "9.9.9"); got != nil {
		t.Errorf("unknown version should have no prior, got %v", got)
	}
}

// TestPriorVersion_LTSCrossBranch — when a project maintains parallel
// LTS branches and the chronologically-adjacent version is on the
// other branch, priorVersion must reach past it to the most recent
// same-major release. Reproduces the @angular/animations 18.2.14 vs
// 19.2.15 scenario where 19.2.15 was published 40 minutes before
// 18.2.14.
func TestPriorVersion_LTSCrossBranch(t *testing.T) {
	versions := []registries.VersionInfo{
		{Version: "18.2.13"},
		{Version: "19.2.14"},
		{Version: "19.2.15"},
		{Version: "18.2.14"},
		{Version: "19.2.16"},
	}
	got := priorVersion(versions, "18.2.14")
	if got == nil || got.Version != "18.2.13" {
		t.Errorf("prior of 18.2.14 should be 18.2.13 (same major), got %v", got)
	}
	got = priorVersion(versions, "19.2.16")
	if got == nil || got.Version != "19.2.15" {
		t.Errorf("prior of 19.2.16 should be 19.2.15 (same major), got %v", got)
	}
}

// TestPriorVersion_MajorBumpFallsBackToChronological — when no
// same-major prior exists (genuine major-version bump), fall back
// to the immediately-preceding chronological version so publisher-
// change / version-diff still catches real maintainer transitions.
func TestPriorVersion_MajorBumpFallsBackToChronological(t *testing.T) {
	versions := []registries.VersionInfo{
		{Version: "4.20.0"},
		{Version: "4.21.0"},
		{Version: "5.0.0"},
	}
	got := priorVersion(versions, "5.0.0")
	if got == nil || got.Version != "4.21.0" {
		t.Errorf("first 5.x should fall back to chronological prior 4.21.0, got %v", got)
	}
}

// TestPriorVersion_ZeroDotMinorIsItsOwnLine — semver convention is
// that 0.minor bumps are breaking, so 0.5.x and 0.6.x are separate
// release lines. priorVersion treats them accordingly.
func TestPriorVersion_ZeroDotMinorIsItsOwnLine(t *testing.T) {
	versions := []registries.VersionInfo{
		{Version: "0.5.0"},
		{Version: "0.5.1"},
		{Version: "0.6.0"},
		{Version: "0.5.2"},
	}
	got := priorVersion(versions, "0.5.2")
	if got == nil || got.Version != "0.5.1" {
		t.Errorf("prior of 0.5.2 should be 0.5.1 (same 0.5 line), got %v", got)
	}
}

func TestMajorKey(t *testing.T) {
	cases := map[string]string{
		"1.2.3":      "1",
		"18.2.14":    "18",
		"1.0.0-rc.1": "1",
		"v1.2.3":     "1",
		"0.5.2":      "0.5",
		"0.5.0-rc.1": "0.5",
		"0":          "0",
		"":           "",
		"latest":     "",
		"foo.bar":    "",
	}
	for in, want := range cases {
		if got := majorKey(in); got != want {
			t.Errorf("majorKey(%q) = %q, want %q", in, got, want)
		}
	}
}
