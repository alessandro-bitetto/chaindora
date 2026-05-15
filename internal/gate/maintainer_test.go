package gate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

type stubMaintainer struct {
	versions []registries.VersionInfo
	err      error
}

func (s stubMaintainer) AllVersions(context.Context, string) ([]registries.VersionInfo, error) {
	return s.versions, s.err
}

func TestMaintainerTrust_ApprovesEstablishedPackage(t *testing.T) {
	now := time.Now()
	// 4 versions over the past 3 years, with a recent regular
	// cadence so no signal fires.
	versions := []registries.VersionInfo{
		{Version: "1.0.0", PublishedAt: now.Add(-3 * 365 * 24 * time.Hour)},
		{Version: "1.0.1", PublishedAt: now.Add(-2 * 365 * 24 * time.Hour)},
		{Version: "1.0.2", PublishedAt: now.Add(-90 * 24 * time.Hour)},
		{Version: "1.0.3", PublishedAt: now.Add(-30 * 24 * time.Hour)},
	}
	m := &MaintainerTrust{
		NPM: stubMaintainer{versions: versions},
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
		NPM: stubMaintainer{versions: versions},
		NewPackageDays:  30,
		MinVersionCount: 3,
		GapThreshold:    6 * 30 * 24 * time.Hour,
	}
	r := m.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "fresh", Version: "0.0.1"})
	if r.Verdict != VerdictWarn {
		t.Errorf("brand-new package should Warn, got %v", r.Verdict)
	}
	if !contains(r.Detail, "brand-new") {
		t.Errorf("detail should mention brand-new, got %q", r.Detail)
	}
	if !contains(r.Detail, "only 1 total") {
		t.Errorf("detail should mention only 1 version, got %q", r.Detail)
	}
}

func TestMaintainerTrust_WarnsOnDormancyGap(t *testing.T) {
	now := time.Now()
	versions := []registries.VersionInfo{
		{Version: "1.0.0", PublishedAt: now.Add(-3 * 365 * 24 * time.Hour)},
		{Version: "1.0.1", PublishedAt: now.Add(-2 * 365 * 24 * time.Hour)},
		{Version: "1.0.2", PublishedAt: now.Add(-2 * 365 * 24 * time.Hour)},
		{Version: "1.0.3", PublishedAt: now.Add(-1 * 24 * time.Hour)}, // sudden bump after 2y
	}
	m := &MaintainerTrust{
		NPM: stubMaintainer{versions: versions},
		NewPackageDays:  30,
		MinVersionCount: 3,
		GapThreshold:    6 * 30 * 24 * time.Hour,
	}
	r := m.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "p", Version: "1.0.3"})
	if r.Verdict != VerdictWarn {
		t.Errorf("2-year dormancy should Warn, got %v: %q", r.Verdict, r.Reason)
	}
	if !contains(r.Detail, "dormancy") {
		t.Errorf("detail should mention dormancy, got %q", r.Detail)
	}
}

func TestMaintainerTrust_UnknownOnNetworkError(t *testing.T) {
	m := &MaintainerTrust{NPM: stubMaintainer{err: errors.New("net")}}
	r := m.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("network error should Unknown, got %v", r.Verdict)
	}
}

func TestMaintainerTrust_NonNPMApproves(t *testing.T) {
	m := &MaintainerTrust{NPM: stubMaintainer{}}
	r := m.Check(context.Background(), PackageRef{Ecosystem: "pypi", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("non-npm should Approve passthrough, got %v", r.Verdict)
	}
}
