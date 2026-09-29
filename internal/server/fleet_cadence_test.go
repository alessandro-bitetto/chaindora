package server

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// TestFleet_PublishCadenceAnomaly — when 4+ distinct versions of
// the same package are first-reported within fleetCadenceWindow
// (24h), the server emits a publish-cadence-anomaly alert.
// Healthy packages don't ship 4 versions in a day; an attacker
// pushing patches to clean up a compromise does.
func TestFleet_PublishCadenceAnomaly(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	agent, _, _ := store.EnrollAgent("a", "host", "test", "", "")

	// Submit 4 different versions of the same package — all within
	// the trailing 24h window (real time, no time-travel needed —
	// the timeline records ReceivedAt = time.Now() each call).
	for _, v := range []string{"1.0.0", "1.0.1", "1.0.2", "1.0.3"} {
		f := findings.Finding{
			Detector:  "predictive:cooldown",
			Category:  findings.CategoryPredictive,
			Ecosystem: inventory.EcosystemNPM,
			Name:      "burstpkg",
			Version:   v,
			Severity:  findings.SeverityMedium,
		}
		if _, err := store.IngestFindings(agent.ID, "test", "test", []findings.Finding{f}); err != nil {
			t.Fatal(err)
		}
	}

	var alert *FindingRecord
	for _, r := range store.QueryFindings(FindingFilter{Limit: 100}) {
		if r.Finding.Detector == "fleet:publish-cadence-anomaly" {
			alert = &r
			break
		}
	}
	if alert == nil {
		t.Fatalf("expected publish-cadence-anomaly alert after 4 versions in window")
	}
	if alert.Finding.Severity != findings.SeverityCritical {
		t.Errorf("cadence alert severity = %q, want CRITICAL", alert.Finding.Severity)
	}
	if !strings.Contains(alert.Finding.Summary, "burstpkg") {
		t.Errorf("cadence alert summary missing package name: %s", alert.Finding.Summary)
	}
}

// TestFleet_NoCadenceAlertForSingleVersion — a single new version
// (even repeated across many agents) must not trip the cadence
// signal. Cadence is about distinct VERSIONS bunched in time, not
// repeated sightings of the same one.
func TestFleet_NoCadenceAlertForSingleVersion(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, _, _ := store.EnrollAgent("a", "h1", "t", "", "")
	b, _, _ := store.EnrollAgent("b", "h2", "t", "", "")
	c, _, _ := store.EnrollAgent("c", "h3", "t", "", "")

	f := findings.Finding{
		Detector:  "predictive:cooldown",
		Category:  findings.CategoryPredictive,
		Ecosystem: inventory.EcosystemNPM,
		Name:      "lodash",
		Version:   "4.17.21",
		Severity:  findings.SeverityMedium,
	}
	for _, agentID := range []string{a.ID, b.ID, c.ID} {
		if _, err := store.IngestFindings(agentID, "t", "t", []findings.Finding{f}); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range store.QueryFindings(FindingFilter{Limit: 100}) {
		if r.Finding.Detector == "fleet:publish-cadence-anomaly" {
			t.Errorf("did not expect cadence alert for single-version submissions: %+v", r.Finding)
		}
	}
}
