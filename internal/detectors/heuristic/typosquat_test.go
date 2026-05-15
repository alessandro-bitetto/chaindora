package heuristic

import (
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

func TestDetectTyposquats(t *testing.T) {
	inv := &inventory.Inventory{
		Packages: []inventory.Package{
			{Ecosystem: inventory.EcosystemNPM, Name: "lodahs", Version: "1.0.0"},         // typo of "lodash"
			{Ecosystem: inventory.EcosystemNPM, Name: "lodash", Version: "4.17.21"},       // legit
			{Ecosystem: inventory.EcosystemPyPI, Name: "requets", Version: "2.0.0"},       // typo of "requests"
			{Ecosystem: inventory.EcosystemNPM, Name: "@scope/legit-pkg", Version: "1.0"}, // scoped, skipped
			{Ecosystem: inventory.EcosystemNPM, Name: "unrelated-pkg-name", Version: "1"}, // far from all
		},
	}
	got := detectTyposquats(inv)
	names := map[string]bool{}
	for _, f := range got {
		names[f.Name] = true
	}
	if !names["lodahs"] {
		t.Errorf("expected lodahs flagged as typosquat; got %v", names)
	}
	if !names["requets"] {
		t.Errorf("expected requets flagged; got %v", names)
	}
	if names["lodash"] {
		t.Errorf("lodash should NOT be flagged — it's the legit package")
	}
	if names["@scope/legit-pkg"] {
		t.Errorf("scoped package should be skipped by typosquat detector")
	}
	if names["unrelated-pkg-name"] {
		t.Errorf("unrelated name flagged as typosquat")
	}
}
