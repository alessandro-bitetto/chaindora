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
