package incident

import (
	"context"
	"strings"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/incidents"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, rel string
		want         bool
	}{
		{"**/data.json", "data.json", true},
		{"**/data.json", "src/data.json", true},
		{"**/data.json", "a/b/c/data.json", true},
		{"**/data.json", "data.json.bak", false},
		{"**/.github/workflows/foo.yml", "x/y/.github/workflows/foo.yml", true},
		{"**/.github/workflows/foo.yml", ".github/workflows/foo.yml", true},
		{"**/.github/workflows/foo.yml", ".github/workflows/bar.yml", false},
		{"src/main.go", "src/main.go", true},
		{"src/main.go", "other/main.go", false},
		{"*.txt", "foo.txt", true},
		{"*.txt", "sub/foo.txt", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.rel); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.rel, got, c.want)
		}
	}
}

func TestNormalizeEcosystem(t *testing.T) {
	cases := []struct {
		in  string
		out inventory.Ecosystem
	}{
		{"npm", inventory.EcosystemNPM},
		{"NPM", inventory.EcosystemNPM},
		{"PyPI", inventory.EcosystemPyPI},
		{"pypi", inventory.EcosystemPyPI},
		{"GitHub Actions", inventory.EcosystemActions},
		{"githubactions", inventory.EcosystemActions},
	}
	for _, c := range cases {
		if got := normalizeEcosystem(c.in); got != c.out {
			t.Errorf("normalizeEcosystem(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"critical", "CRITICAL"},
		{"HIGH", "HIGH"},
		{"medium", "MEDIUM"},
		{"moderate", "MEDIUM"},
		{"low", "LOW"},
		{"???", "UNKNOWN"},
	}
	for _, c := range cases {
		if got := parseSeverity(c.in); string(got) != c.want {
			t.Errorf("parseSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDetectWildcardVersionMatchesAll(t *testing.T) {
	inv := &inventory.Inventory{Packages: []inventory.Package{
		{Ecosystem: inventory.EcosystemPyPI, Name: "torchtriton", Version: "0.0.1", PURL: "pkg:pypi/torchtriton@0.0.1"},
		{Ecosystem: inventory.EcosystemPyPI, Name: "torchtriton", Version: "9.9.9", PURL: "pkg:pypi/torchtriton@9.9.9"},
		{Ecosystem: inventory.EcosystemPyPI, Name: "innocent", Version: "1.0.0", PURL: "pkg:pypi/innocent@1.0.0"},
	}}
	d := New([]*incidents.Incident{{
		ID:       "PYPI-TYPO-TEST",
		Name:     "wildcard test",
		Severity: "critical",
		Packages: []incidents.IncidentPackage{
			{Ecosystem: "PyPI", Name: "torchtriton", Versions: []string{"*"}},
		},
	}})
	out, err := d.Detect(context.Background(), inv, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings (both torchtriton versions), got %d: %+v", len(out), out)
	}
	for _, f := range out {
		if f.Name != "torchtriton" {
			t.Errorf("unexpected match: %+v", f)
		}
	}
}

func TestPlanFixUpgradeNPM(t *testing.T) {
	f := findings.Finding{
		Detector:     "incident-pack",
		PURL:         "pkg:npm/chalk@5.6.1",
		Ecosystem:    inventory.EcosystemNPM,
		Name:         "chalk",
		Version:      "5.6.1",
		VulnID:       "NPM-QIX-COMPROMISE-2025-09",
		Severity:     findings.SeverityCritical,
		FixUpgradeTo: "5.6.2",
		PostCompromise: []string{
			"rotate npm tokens published during the attack window",
		},
	}
	plan, ok := PlanFix(f)
	if !ok || plan == nil {
		t.Fatal("expected plan")
	}
	if plan.Category != findings.FixSemiSafe {
		t.Errorf("category: got %v, want FixSemiSafe", plan.Category)
	}
	if plan.Command != "npm install chalk@5.6.2" {
		t.Errorf("command: got %q", plan.Command)
	}
	if !strings.Contains(strings.Join(plan.ManualSteps, "\n"), "rotate npm tokens") {
		t.Errorf("post_compromise step missing: %+v", plan.ManualSteps)
	}
}

func TestPlanFixUpgradePyPI(t *testing.T) {
	f := findings.Finding{
		Detector:     "incident-pack",
		PURL:         "pkg:pypi/ultralytics@8.3.41",
		Ecosystem:    inventory.EcosystemPyPI,
		Name:         "ultralytics",
		Version:      "8.3.41",
		VulnID:       "PYPI-ULTRALYTICS-2024-12",
		Severity:     findings.SeverityCritical,
		FixUpgradeTo: "8.3.43",
	}
	plan, ok := PlanFix(f)
	if !ok {
		t.Fatal("expected plan")
	}
	want := "python3 -m pip install --upgrade ultralytics==8.3.43"
	if plan.Command != want {
		t.Errorf("command: got %q, want %q", plan.Command, want)
	}
}

func TestPlanFixUninstallFallback(t *testing.T) {
	// No safe_version → uninstall fallback (existing behaviour preserved).
	f := findings.Finding{
		Detector:  "incident-pack",
		PURL:      "pkg:npm/evil-pkg@1.0.0",
		Ecosystem: inventory.EcosystemNPM,
		Name:      "evil-pkg",
		Version:   "1.0.0",
		VulnID:    "NPM-EVIL-2026",
		Severity:  findings.SeverityHigh,
	}
	plan, ok := PlanFix(f)
	if !ok {
		t.Fatal("expected plan")
	}
	if plan.Command != "npm uninstall evil-pkg" {
		t.Errorf("command: got %q", plan.Command)
	}
}

func TestPlanFixHomebrew(t *testing.T) {
	f := findings.Finding{
		Detector:     "incident-pack",
		PURL:         "pkg:brew/xz@5.6.1",
		Ecosystem:    inventory.EcosystemHomebrew,
		Name:         "xz",
		Version:      "5.6.1",
		VulnID:       "CVE-2024-3094",
		Severity:     findings.SeverityCritical,
		FixUpgradeTo: "5.6.2",
	}
	plan, ok := PlanFix(f)
	if !ok {
		t.Fatal("expected plan")
	}
	if plan.Command != "brew upgrade xz" {
		t.Errorf("command: got %q", plan.Command)
	}
	joined := strings.Join(plan.ManualSteps, "\n")
	if !strings.Contains(joined, "5.6.2") {
		t.Errorf("expected safe-version verification step, got: %s", joined)
	}
}

func TestPlanFixFileArtifactSurfacesPostCompromise(t *testing.T) {
	f := findings.Finding{
		Detector:   "incident-pack",
		VulnID:     "NPM-SHAI-HULUD-2025-09",
		Severity:   findings.SeverityCritical,
		SourcePath: "/repo/.github/workflows/shai-hulud-workflow.yml",
		PostCompromise: []string{
			"rotate every npm/GitHub/AWS token reachable from the affected machine",
		},
	}
	plan, ok := PlanFix(f)
	if !ok {
		t.Fatal("expected plan")
	}
	if plan.Category != findings.FixSafe {
		t.Errorf("category: got %v", plan.Category)
	}
	if !strings.Contains(strings.Join(plan.ManualSteps, "\n"), "rotate every npm") {
		t.Errorf("post_compromise step missing on file-artifact plan: %+v", plan.ManualSteps)
	}
}
