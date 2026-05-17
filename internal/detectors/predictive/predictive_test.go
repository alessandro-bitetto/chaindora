package predictive

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/gate"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

// stubProbe is a minimal VersionProbe satisfying the interface for
// detector-level tests. Mirrors gate's internal stubProbe but lives
// here so the predictive package's tests stay self-contained.
type stubProbe struct {
	publishedAt map[string]time.Time
	publisher   map[string]string
	versions    []registries.VersionInfo
}

func (s stubProbe) PublishedAtVersion(_ context.Context, _, v string) (time.Time, error) {
	return s.publishedAt[v], nil
}
func (s stubProbe) PublisherOfVersion(_ context.Context, _, v string) (string, error) {
	return s.publisher[v], nil
}
func (s stubProbe) AllVersions(_ context.Context, _ string) ([]registries.VersionInfo, error) {
	return s.versions, nil
}
func (s stubProbe) TarballURL(_ context.Context, _, _ string) (string, error) {
	return "", nil
}
func (s stubProbe) FetchTarball(_ context.Context, _ string, _ io.Writer) error { return nil }

// TestPredictive_EmitsCooldownForRecentVersion verifies that an
// installed package whose version was published within the cooldown
// window produces a Medium-severity finding under the predictive
// detector. This is the headline scan-side use case the user
// asked about: catch "you installed a package during its attack
// window" after the fact.
func TestPredictive_EmitsCooldownForRecentVersion(t *testing.T) {
	now := time.Now()
	probe := stubProbe{
		publishedAt: map[string]time.Time{
			"1.0.0": now.Add(-2 * time.Hour), // 2 hours ago — well inside 72h cooldown
		},
		publisher: map[string]string{
			"1.0.0": "alice",
		},
		versions: []registries.VersionInfo{
			{Version: "1.0.0", PublishedAt: now.Add(-2 * time.Hour), Publisher: "alice"},
		},
	}
	probes := gate.NewProbes()
	probes.Register("npm", probe)

	inv := &inventory.Inventory{
		Packages: []inventory.Package{
			{
				Ecosystem:  inventory.EcosystemNPM,
				Name:       "freshpkg",
				Version:    "1.0.0",
				SourcePath: "package-lock.json",
			},
		},
	}

	det := New(probes, 72*time.Hour, nil)
	out, err := det.Detect(context.Background(), inv)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	var cooldown *findings.Finding
	for i := range out {
		if out[i].Detector == "predictive:cooldown" {
			cooldown = &out[i]
			break
		}
	}
	if cooldown == nil {
		t.Fatalf("expected a predictive:cooldown finding, got %d findings: %+v", len(out), out)
	}
	if cooldown.Severity != findings.SeverityMedium {
		t.Errorf("cooldown finding severity = %q, want Medium", cooldown.Severity)
	}
	if cooldown.Category != findings.CategoryPredictive {
		t.Errorf("cooldown finding category = %q, want predictive", cooldown.Category)
	}
	if cooldown.Name != "freshpkg" || cooldown.Version != "1.0.0" {
		t.Errorf("cooldown finding ref mismatch: %s@%s", cooldown.Name, cooldown.Version)
	}
}

// TestPredictive_NoFindingsWhenPackageIsMature verifies the
// "happy path" — a months-old package with no publisher churn
// shouldn't trip any predictive signal.
func TestPredictive_NoFindingsWhenPackageIsMature(t *testing.T) {
	now := time.Now()
	probe := stubProbe{
		publishedAt: map[string]time.Time{
			"4.17.21": now.AddDate(-3, 0, 0),
			"4.17.20": now.AddDate(-3, -1, 0),
		},
		publisher: map[string]string{
			"4.17.21": "lodash-bot",
			"4.17.20": "lodash-bot",
		},
		versions: []registries.VersionInfo{
			{Version: "4.17.20", PublishedAt: now.AddDate(-3, -1, 0), Publisher: "lodash-bot"},
			{Version: "4.17.21", PublishedAt: now.AddDate(-3, 0, 0), Publisher: "lodash-bot"},
		},
	}
	probes := gate.NewProbes()
	probes.Register("npm", probe)

	inv := &inventory.Inventory{
		Packages: []inventory.Package{
			{Ecosystem: inventory.EcosystemNPM, Name: "lodash", Version: "4.17.21"},
		},
	}
	det := New(probes, 72*time.Hour, nil)
	out, _ := det.Detect(context.Background(), inv)
	for _, f := range out {
		switch f.Detector {
		case "predictive:cooldown", "predictive:publisher-change":
			t.Errorf("did not expect %s for mature package: %+v", f.Detector, f)
		}
	}
}

// TestPredictive_SkipsUnknownVerdicts verifies the v0.15.3
// regression: when a checker returns Verdict=Unknown (typically
// because no registry probe is registered for the ecosystem —
// NuGet / Packagist / Pub / Hex / ... as of v0.15.x), the
// predictive detector silences the finding. Pre-v0.15.3 a typical
// .NET project produced 22+ "no registry probe for nuget" Low
// findings that drowned out the real signal.
func TestPredictive_SkipsUnknownVerdicts(t *testing.T) {
	// Build a probe table with ONLY npm registered; the inventory
	// has a NuGet package which will hit "no probe" Unknown for
	// every NuGet-targeted checker.
	probes := gate.NewProbes()
	probes.Register("npm", stubProbe{}) // npm present, nuget absent

	inv := &inventory.Inventory{
		Packages: []inventory.Package{
			{
				Ecosystem:  inventory.EcosystemNuGet,
				Name:       "AWSSDK.S3",
				Version:    "4.0.2",
				SourcePath: "Frameflows.Api.csproj",
			},
		},
	}
	det := New(probes, 72*time.Hour, nil)
	out, err := det.Detect(context.Background(), inv)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	for _, f := range out {
		if strings.Contains(f.Summary, "no registry probe") {
			t.Errorf("did not expect 'no registry probe' finding to leak through: %+v", f)
		}
	}
}

// TestPredictive_SkipsUngatedEcosystems verifies that inventory
// entries from ecosystems with no gate-side probe (CI YAMLs, host
// forensics artifacts) don't produce predictive findings and don't
// crash the detector.
func TestPredictive_SkipsUngatedEcosystems(t *testing.T) {
	inv := &inventory.Inventory{
		Packages: []inventory.Package{
			{Ecosystem: inventory.EcosystemActions, Name: "actions/checkout", Version: "v4"},
			{Ecosystem: inventory.EcosystemHomebrew, Name: "git", Version: "2.43.0"},
		},
	}
	det := New(gate.NewProbes(), 72*time.Hour, nil)
	out, err := det.Detect(context.Background(), inv)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected zero findings for ungated ecosystems, got %d: %+v", len(out), out)
	}
}
