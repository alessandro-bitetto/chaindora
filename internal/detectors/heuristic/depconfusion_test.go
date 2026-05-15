package heuristic

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

func TestDetectDepConfusionNoNpmrc(t *testing.T) {
	tmp := t.TempDir()
	inv := &inventory.Inventory{
		Packages: []inventory.Package{
			{Ecosystem: inventory.EcosystemNPM, Name: "@my-company/auth", Version: "1.0.0"},
			{Ecosystem: inventory.EcosystemNPM, Name: "lodash", Version: "4.17.21"},
		},
	}
	got := detectDepConfusion(inv, tmp)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding (scoped, no .npmrc), got %d: %+v", len(got), got)
	}
	if got[0].Severity != findings.SeverityMedium {
		t.Errorf("no-.npmrc case should be MEDIUM, got %q", got[0].Severity)
	}
}

func TestDetectDepConfusionNpmrcWithoutScope(t *testing.T) {
	tmp := t.TempDir()
	npmrc := `# comment
registry=https://registry.npmjs.org/
@another-scope:registry=https://internal.example.com/npm
`
	if err := os.WriteFile(filepath.Join(tmp, ".npmrc"), []byte(npmrc), 0644); err != nil {
		t.Fatal(err)
	}
	inv := &inventory.Inventory{
		Packages: []inventory.Package{
			{Ecosystem: inventory.EcosystemNPM, Name: "@my-company/auth", Version: "1.0.0"},
			{Ecosystem: inventory.EcosystemNPM, Name: "@another-scope/foo", Version: "2.0.0"},
		},
	}
	got := detectDepConfusion(inv, tmp)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding (only @my-company is uncovered), got %d: %+v", len(got), got)
	}
	if got[0].Name != "@my-company/auth" {
		t.Errorf("wrong scope flagged: %s", got[0].Name)
	}
	if got[0].Severity != findings.SeverityLow {
		t.Errorf(".npmrc exists but no rule for this scope → LOW, got %q", got[0].Severity)
	}
}

func TestDetectDepConfusionDedupesScopes(t *testing.T) {
	tmp := t.TempDir()
	inv := &inventory.Inventory{
		Packages: []inventory.Package{
			{Ecosystem: inventory.EcosystemNPM, Name: "@x/a", Version: "1.0"},
			{Ecosystem: inventory.EcosystemNPM, Name: "@x/b", Version: "1.0"},
			{Ecosystem: inventory.EcosystemNPM, Name: "@x/c", Version: "1.0"},
		},
	}
	got := detectDepConfusion(inv, tmp)
	if len(got) != 1 {
		t.Errorf("expected dedup to 1 finding per scope, got %d", len(got))
	}
}
