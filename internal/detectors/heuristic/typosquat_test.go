package heuristic

import (
	"context"
	"testing"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// Typosquat needs registry evidence post-v0.6.0: Levenshtein closeness
// alone isn't enough. The fakeProbe lets us simulate "this package is
// 3 days old with 12 downloads" vs "this package is 10 years old with
// 50k downloads" without hitting the network.

func TestTyposquat_FreshAndLowTraffic_Fires(t *testing.T) {
	probe := newFakeProbe()
	probe.published["lodahs"] = time.Now().AddDate(0, 0, -3) // 3 days old
	probe.downloads["lodahs"] = 5                            // tiny traffic
	inv := &inventory.Inventory{Packages: []inventory.Package{
		{Ecosystem: inventory.EcosystemNPM, Name: "lodahs", Version: "1.0.0"},
	}}
	got := detectTyposquats(context.Background(), inv, Config{NPMProbe: probe})
	if len(got) != 1 {
		t.Fatalf("expected 1 typosquat finding, got %d", len(got))
	}
	if got[0].Severity != findings.SeverityHigh {
		t.Errorf("3-day-old typosquat should be HIGH, got %q", got[0].Severity)
	}
}

func TestTyposquat_MatureAndPopular_Suppressed(t *testing.T) {
	// "jsonparse" is Levenshtein-near "json-parse" but it's a real
	// 10-year-old package — should NOT fire as a typosquat.
	probe := newFakeProbe()
	probe.published["jsonparse"] = time.Now().AddDate(-10, 0, 0)
	probe.downloads["jsonparse"] = 5_000_000
	inv := &inventory.Inventory{Packages: []inventory.Package{
		{Ecosystem: inventory.EcosystemNPM, Name: "jsonparse", Version: "1.3.1"},
	}}
	got := detectTyposquats(context.Background(), inv, Config{NPMProbe: probe})
	if len(got) != 0 {
		t.Errorf("mature + popular near-name should be suppressed, got %+v", got)
	}
}

func TestTyposquat_OldButLowTraffic_StillSuppressed(t *testing.T) {
	probe := newFakeProbe()
	probe.published["lodahs"] = time.Now().AddDate(-5, 0, 0) // 5 years old
	probe.downloads["lodahs"] = 2                            // barely used
	inv := &inventory.Inventory{Packages: []inventory.Package{
		{Ecosystem: inventory.EcosystemNPM, Name: "lodahs", Version: "1.0.0"},
	}}
	got := detectTyposquats(context.Background(), inv, Config{NPMProbe: probe})
	if len(got) != 0 {
		t.Errorf("5-year-old name should be suppressed regardless of downloads, got %+v", got)
	}
}

func TestTyposquat_NoEvidence_DoesNotFire(t *testing.T) {
	// Offline / no probe → we can't tell typosquat from legitimate
	// neighbour-name. Conservative: skip.
	inv := &inventory.Inventory{Packages: []inventory.Package{
		{Ecosystem: inventory.EcosystemNPM, Name: "lodahs", Version: "1.0.0"},
	}}
	got := detectTyposquats(context.Background(), inv, Config{})
	if len(got) != 0 {
		t.Errorf("offline mode should not fire typosquat without evidence, got %+v", got)
	}
}

func TestTyposquat_ScopedSkipped(t *testing.T) {
	probe := newFakeProbe()
	probe.published["@scope/legit-pkg"] = time.Now()
	inv := &inventory.Inventory{Packages: []inventory.Package{
		{Ecosystem: inventory.EcosystemNPM, Name: "@scope/legit-pkg", Version: "1.0"},
	}}
	got := detectTyposquats(context.Background(), inv, Config{NPMProbe: probe})
	if len(got) != 0 {
		t.Errorf("scoped packages should bypass typosquat — got %+v", got)
	}
}
