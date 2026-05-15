package gate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

type stubPublisher struct {
	publisherForVersion map[string]string
	versions            []registries.VersionInfo
	publisherErr        error
	versionsErr         error
}

func (s stubPublisher) PublisherOfVersion(_ context.Context, _, version string) (string, error) {
	if s.publisherErr != nil {
		return "", s.publisherErr
	}
	return s.publisherForVersion[version], nil
}

func (s stubPublisher) AllVersions(_ context.Context, _ string) ([]registries.VersionInfo, error) {
	if s.versionsErr != nil {
		return nil, s.versionsErr
	}
	return s.versions, nil
}

func TestPublisherChange_ApprovesSamePublisher(t *testing.T) {
	versions := []registries.VersionInfo{
		{Version: "1.0.0", Publisher: "alice", PublishedAt: time.Now().Add(-30 * 24 * time.Hour)},
		{Version: "1.0.1", Publisher: "alice", PublishedAt: time.Now().Add(-7 * 24 * time.Hour)},
	}
	p := &PublisherChange{NPM: stubPublisher{
		publisherForVersion: map[string]string{"1.0.0": "alice", "1.0.1": "alice"},
		versions:            versions,
	}}
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
	p := &PublisherChange{NPM: stubPublisher{
		publisherForVersion: map[string]string{"1.0.0": "alice", "1.0.1": "bob"},
		versions:            versions,
	}}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "pkg", Version: "1.0.1"})
	if r.Verdict != VerdictWarn {
		t.Errorf("publisher change should Warn (Strict→block), got %v: %q", r.Verdict, r.Reason)
	}
	if !contains(r.Reason, "alice") || !contains(r.Reason, "bob") {
		t.Errorf("reason should name both publishers, got %q", r.Reason)
	}
}

func TestPublisherChange_WarnsOnFirstPublish(t *testing.T) {
	versions := []registries.VersionInfo{
		{Version: "0.1.0", Publisher: "alice", PublishedAt: time.Now()},
	}
	p := &PublisherChange{NPM: stubPublisher{
		publisherForVersion: map[string]string{"0.1.0": "alice"},
		versions:            versions,
	}}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "pkg", Version: "0.1.0"})
	if r.Verdict != VerdictWarn {
		t.Errorf("first publish should Warn (brand-new package signal), got %v", r.Verdict)
	}
}

func TestPublisherChange_UnknownOnNetworkError(t *testing.T) {
	p := &PublisherChange{NPM: stubPublisher{publisherErr: errors.New("dns failure")}}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("network error should Unknown, got %v", r.Verdict)
	}
}

func TestPublisherChange_UnknownWhenCurrentPublisherMissing(t *testing.T) {
	p := &PublisherChange{NPM: stubPublisher{
		publisherForVersion: map[string]string{"1.0.0": ""}, // older publish, no _npmUser
		versions:            []registries.VersionInfo{{Version: "1.0.0", Publisher: ""}},
	}}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("missing publisher should Unknown, got %v", r.Verdict)
	}
}

func TestPublisherChange_NonNPMApprovesPassthrough(t *testing.T) {
	p := &PublisherChange{NPM: stubPublisher{}}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "pypi", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("non-npm should Approve (passthrough), got %v", r.Verdict)
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
