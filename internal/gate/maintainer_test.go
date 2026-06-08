package gate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

func TestMaintainerTrust_ApprovesEstablishedPackage(t *testing.T) {
	now := time.Now()
	versions := []registries.VersionInfo{
		{Version: "1.0.0", PublishedAt: now.Add(-3 * 365 * 24 * time.Hour)},
		{Version: "1.0.1", PublishedAt: now.Add(-2 * 365 * 24 * time.Hour)},
		{Version: "1.0.2", PublishedAt: now.Add(-90 * 24 * time.Hour)},
		{Version: "1.0.3", PublishedAt: now.Add(-30 * 24 * time.Hour)},
	}
	m := &MaintainerTrust{
		Probes:          probesWith("npm", stubProbe{versions: versions}),
		NewPackageDays:  30,
		MinVersionCount: 3,
		GapThreshold:    6 * 30 * 24 * time.Hour,
	}
	r := m.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "p", Version: "1.0.3"})
	if r.Verdict != VerdictApprove {
		t.Errorf("established package should Approve, got %v: %q\n%s", r.Verdict, r.Reason, r.Detail)
	}
}

func TestMaintainerTrust_WarnsOnBrandNewPackage(t *testing.T) {
	now := time.Now()
	versions := []registries.VersionInfo{
		{Version: "0.0.1", PublishedAt: now.Add(-2 * 24 * time.Hour)},
	}
	m := &MaintainerTrust{
		Probes:          probesWith("npm", stubProbe{versions: versions}),
		NewPackageDays:  30,
		MinVersionCount: 3,
		GapThreshold:    6 * 30 * 24 * time.Hour,
	}
	r := m.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "fresh", Version: "0.0.1"})
	if r.Verdict != VerdictWarn {
		t.Errorf("brand-new package should Warn, got %v", r.Verdict)
	}
}

// Dormancy ALONE (a single soft signal) is below the Warn threshold —
// mature packages legitimately go quiet for years. It must Approve.
func TestMaintainerTrust_DormancyAloneBelowThreshold(t *testing.T) {
	now := time.Now()
	versions := []registries.VersionInfo{
		{Version: "1.0.0", PublishedAt: now.Add(-3 * 365 * 24 * time.Hour)},
		{Version: "1.0.1", PublishedAt: now.Add(-2 * 365 * 24 * time.Hour)},
		{Version: "1.0.2", PublishedAt: now.Add(-2 * 365 * 24 * time.Hour)},
		{Version: "1.0.3", PublishedAt: now.Add(-1 * 24 * time.Hour)},
	}
	m := &MaintainerTrust{
		Probes:          probesWith("npm", stubProbe{versions: versions}),
		NewPackageDays:  30,
		MinVersionCount: 3,
		GapThreshold:    6 * 30 * 24 * time.Hour,
	}
	r := m.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "p", Version: "1.0.3"})
	if r.Verdict != VerdictApprove {
		t.Errorf("dormancy alone is one signal (below threshold) → Approve, got %v: %q", r.Verdict, r.Reason)
	}
}

// A composite — few-versions + dormancy — crosses the threshold and Warns.
func TestMaintainerTrust_WarnsOnCompositeSignals(t *testing.T) {
	now := time.Now()
	versions := []registries.VersionInfo{
		{Version: "1.0.0", PublishedAt: now.Add(-3 * 365 * 24 * time.Hour)},
		{Version: "1.0.1", PublishedAt: now.Add(-1 * 24 * time.Hour)},
	}
	m := &MaintainerTrust{
		Probes:          probesWith("npm", stubProbe{versions: versions}),
		NewPackageDays:  30,
		MinVersionCount: 3, // 2 versions < 3 → few-versions signal
		GapThreshold:    6 * 30 * 24 * time.Hour,
	}
	r := m.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "p", Version: "1.0.1"})
	if r.Verdict != VerdictWarn {
		t.Errorf("few-versions + dormancy (2 signals) should Warn, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestMaintainerTrust_UnknownOnNetworkError(t *testing.T) {
	m := &MaintainerTrust{Probes: probesWith("npm", stubProbe{versionsErr: errors.New("net")})}
	r := m.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("network error should Unknown, got %v", r.Verdict)
	}
}

func TestMaintainerTrust_UnregisteredEcosystemPassthrough(t *testing.T) {
	m := &MaintainerTrust{Probes: NewProbes()}
	r := m.Check(context.Background(), PackageRef{Ecosystem: "exotic", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("unregistered ecosystem should Approve passthrough, got %v", r.Verdict)
	}
}
