package server

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// TestFleet_RepublishDetectionAcrossAgents verifies the headline
// v0.15 fleet signal: agent A reports a package with integrity X,
// agent B later reports the same name@version with integrity Y,
// the server emits a synthetic "fleet:republish-detected" finding.
//
// This catches the supply-chain pattern where a registry served
// different bytes to different agents during an attack window —
// even when no single agent has enough local history to fire the
// per-machine republish-guard.
func TestFleet_RepublishDetectionAcrossAgents(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Enroll two agents without a shared secret (empty
	// enrollmentSecret + matching empty providedSecret = open mode).
	agentA, _, err := store.EnrollAgent("alice", "laptop-a", "test", "", "")
	if err != nil {
		t.Fatal(err)
	}
	agentB, _, err := store.EnrollAgent("bob", "laptop-b", "test", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Agent A reports lodash@4.17.21 with integrity X.
	findingA := findings.Finding{
		Detector:  "predictive:cooldown",
		Category:  findings.CategoryPredictive,
		Ecosystem: inventory.EcosystemNPM,
		Name:      "lodash",
		Version:   "4.17.21",
		Severity:  findings.SeverityMedium,
		Integrity: "sha512-AAA",
	}
	if _, err := store.IngestFindings(agentA.ID, "test", "test", []findings.Finding{findingA}); err != nil {
		t.Fatal(err)
	}

	// Agent B reports the same name@version with DIFFERENT integrity Y.
	findingB := findings.Finding{
		Detector:  "predictive:cooldown",
		Category:  findings.CategoryPredictive,
		Ecosystem: inventory.EcosystemNPM,
		Name:      "lodash",
		Version:   "4.17.21",
		Severity:  findings.SeverityMedium,
		Integrity: "sha512-BBB",
	}
	if _, err := store.IngestFindings(agentB.ID, "test", "test", []findings.Finding{findingB}); err != nil {
		t.Fatal(err)
	}

	// Server should have appended a fleet:republish-detected finding.
	records := store.QueryFindings(FindingFilter{Limit: 100})
	var fleetAlert *FindingRecord
	for i := range records {
		if records[i].Finding.Detector == "fleet:republish-detected" {
			fleetAlert = &records[i]
			break
		}
	}
	if fleetAlert == nil {
		t.Fatalf("expected fleet:republish-detected finding after divergent submission; got %d findings", len(records))
	}
	if fleetAlert.Finding.Severity != findings.SeverityCritical {
		t.Errorf("fleet alert severity = %q, want CRITICAL", fleetAlert.Finding.Severity)
	}
	if !strings.Contains(fleetAlert.Finding.Summary, "lodash@4.17.21") {
		t.Errorf("fleet alert summary missing package ref: %s", fleetAlert.Finding.Summary)
	}
	if !strings.Contains(fleetAlert.Finding.Summary, agentA.ID) {
		t.Errorf("fleet alert summary should name the first-reporting agent: %s", fleetAlert.Finding.Summary)
	}
}

// TestFleet_SameIntegrityNoAlert verifies the happy path — two
// agents reporting the SAME name@version with the SAME integrity
// must not fire a fleet alert. (That's the common case across a
// healthy fleet.)
func TestFleet_SameIntegrityNoAlert(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	agentA, _, _ := store.EnrollAgent("alice", "laptop-a", "test", "", "")
	agentB, _, _ := store.EnrollAgent("bob", "laptop-b", "test", "", "")

	f := findings.Finding{
		Detector:  "predictive:cooldown",
		Category:  findings.CategoryPredictive,
		Ecosystem: inventory.EcosystemNPM,
		Name:      "lodash",
		Version:   "4.17.21",
		Severity:  findings.SeverityMedium,
		Integrity: "sha512-AAA",
	}
	if _, err := store.IngestFindings(agentA.ID, "test", "test", []findings.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.IngestFindings(agentB.ID, "test", "test", []findings.Finding{f}); err != nil {
		t.Fatal(err)
	}

	for _, r := range store.QueryFindings(FindingFilter{Limit: 100}) {
		if r.Finding.Detector == "fleet:republish-detected" {
			t.Errorf("did not expect fleet alert when both agents report identical integrity: %+v", r.Finding)
		}
	}
}

// TestFleet_NoIntegrityNoTracking verifies that findings without
// an Integrity field don't populate the fleet observation map —
// without a hash, there's nothing to compare, so we must not
// emit false positives.
func TestFleet_NoIntegrityNoTracking(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	agent, _, _ := store.EnrollAgent("alice", "laptop", "test", "", "")
	f := findings.Finding{
		Detector:  "predictive:cooldown",
		Category:  findings.CategoryPredictive,
		Ecosystem: inventory.EcosystemNPM,
		Name:      "lodash",
		Version:   "4.17.21",
		Severity:  findings.SeverityMedium,
		// Integrity left empty
	}
	if _, err := store.IngestFindings(agent.ID, "test", "test", []findings.Finding{f}); err != nil {
		t.Fatal(err)
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if len(store.state.PackageObservations) != 0 {
		t.Errorf("expected no PackageObservations for empty-integrity finding, got %d", len(store.state.PackageObservations))
	}
}
