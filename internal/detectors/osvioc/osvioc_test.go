package osvioc

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
	"github.com/alessandro-bitetto/chaindora/internal/osv"
)

func TestCategoryForOSVID(t *testing.T) {
	cases := []struct {
		id   string
		want findings.Category
	}{
		{"MAL-2024-1234", findings.CategorySupplyChainAttack},
		{"MAL-0001", findings.CategorySupplyChainAttack},
		{"CVE-2024-1234", findings.CategoryDependencyCVE},
		{"GHSA-aaaa-bbbb-cccc", findings.CategoryDependencyCVE},
		{"PYSEC-2024-99", findings.CategoryDependencyCVE},
		{"RUSTSEC-2024-1", findings.CategoryDependencyCVE},
		{"", findings.CategoryDependencyCVE}, // empty falls to CVE bucket
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			if got := categoryForOSVID(c.id); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestOsvEcosystem_CoversTier1Ecosystems(t *testing.T) {
	// Tier 1 ecosystems must map to a non-empty OSV name. The empty
	// return value is reserved for ecosystems OSV's query API doesn't
	// support (Docker without a registry-qualified form, CI systems,
	// browser/IDE extensions).
	tier1 := []inventory.Ecosystem{
		inventory.EcosystemNPM,
		inventory.EcosystemPyPI,
		inventory.EcosystemGoModules,
		inventory.EcosystemRubyGems,
		inventory.EcosystemCrates,
		inventory.EcosystemMavenCentral,
		inventory.EcosystemNuGet,
		inventory.EcosystemPackagist,
		inventory.EcosystemPub,
		inventory.EcosystemHex,
		inventory.EcosystemSwift,
		inventory.EcosystemHackage,
		inventory.EcosystemCRAN,
		inventory.EcosystemConan,
	}
	for _, e := range tier1 {
		t.Run(string(e), func(t *testing.T) {
			if got := osvEcosystem(e); got == "" {
				t.Errorf("ecosystem %q must map to non-empty OSV name", e)
			}
		})
	}
}

func TestOsvEcosystem_UnsupportedReturnsEmpty(t *testing.T) {
	// These ecosystems intentionally have no OSV coverage. An empty
	// return value tells the OSV detector to skip the package
	// rather than emit a misleading "no advisories" finding for an
	// ecosystem OSV doesn't index. Docker is the headline case (OCI
	// works only with registry-qualified ecosystem strings, which
	// the v0.5 work intentionally deferred).
	unsupported := []inventory.Ecosystem{
		inventory.EcosystemDocker,
		inventory.EcosystemActions,
		inventory.EcosystemGitLabCI,
		inventory.EcosystemBitbucketPipes,
		inventory.EcosystemCircleCIOrbs,
		inventory.EcosystemAzurePipelines,
		inventory.EcosystemBrowserExt,
		inventory.EcosystemIDEExt,
		inventory.EcosystemHomebrew,
		inventory.EcosystemDebian,
	}
	for _, e := range unsupported {
		t.Run(string(e), func(t *testing.T) {
			if got := osvEcosystem(e); got != "" {
				t.Errorf("ecosystem %q should not have OSV mapping yet, got %q", e, got)
			}
		})
	}
}

func TestFirstLine(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"single line", "single line"},
		{"first\nsecond", "first"},
		{"\nleading", ""},
		{"", ""},
		{"trailing\n", "trailing"},
		{"a\nb\nc", "a"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := firstLine(c.in); got != c.want {
				t.Errorf("firstLine(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestSeverityFromVuln_MapsByHighest(t *testing.T) {
	cases := []struct {
		name string
		v    *osv.Vulnerability
		want findings.Severity
	}{
		{"nil", nil, findings.SeverityUnknown},
		{"empty severity", &osv.Vulnerability{}, findings.SeverityUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := severityFromVuln(c.v); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestPlanFix_NoOpForNonOsvFinding asserts the dispatcher contract:
// PlanFix only handles findings from its own detector.
func TestPlanFix_NoOpForNonOsvFinding(t *testing.T) {
	f := findings.Finding{Detector: "heuristic:typosquat", Name: "lodash"}
	plan, ok := PlanFix(f)
	if ok || plan != nil {
		t.Errorf("PlanFix on non-osvioc finding should return (nil, false); got (%+v, %v)", plan, ok)
	}
}

func TestPlanFix_GlobalNPM(t *testing.T) {
	f := findings.Finding{
		Detector: "osv-ioc", Name: "lodash", Version: "1.0.0",
		VulnID: "CVE-2024-X", SourcePath: "npm:global",
	}
	plan, ok := PlanFix(f)
	if !ok || plan == nil {
		t.Fatal("expected plan, got nil")
	}
	if plan.Category != findings.FixSafe {
		t.Errorf("global npm should be FixSafe, got %v", plan.Category)
	}
	if !strings.Contains(plan.Command, "npm install -g lodash@latest") {
		t.Errorf("command missing npm install -g; got %q", plan.Command)
	}
}

func TestPlanFix_GlobalPip(t *testing.T) {
	f := findings.Finding{
		Detector: "osv-ioc", Name: "requests", Version: "2.0",
		VulnID: "CVE-2024-Y", SourcePath: "pip:global",
	}
	plan, ok := PlanFix(f)
	if !ok || plan.Category != findings.FixSafe {
		t.Fatalf("expected FixSafe plan, got %+v ok=%v", plan, ok)
	}
	if !strings.Contains(plan.Command, "python3 -m pip install --upgrade --user requests") {
		t.Errorf("unexpected command: %q", plan.Command)
	}
}

func TestPlanFix_GlobalBrew(t *testing.T) {
	f := findings.Finding{
		Detector: "osv-ioc", Name: "jq", Version: "1.6",
		VulnID: "CVE-2024-Z", SourcePath: "brew:global",
	}
	plan, ok := PlanFix(f)
	if !ok || plan.Category != findings.FixSafe || !strings.Contains(plan.Command, "brew upgrade jq") {
		t.Errorf("expected brew upgrade jq, got %+v ok=%v", plan, ok)
	}
}

func TestPlanFix_DpkgGoesManual(t *testing.T) {
	// dpkg upgrades need sudo + service-restart caution → FixUnsafe,
	// manual-only.
	f := findings.Finding{
		Detector: "osv-ioc", Name: "openssl", Version: "1.0.2",
		VulnID: "CVE-2014-0160", SourcePath: "dpkg:global",
	}
	plan, ok := PlanFix(f)
	if !ok || plan.Category != findings.FixUnsafe {
		t.Errorf("dpkg should be FixUnsafe, got cat=%v ok=%v", plan.Category, ok)
	}
	if plan.Command != "" {
		t.Errorf("FixUnsafe must not auto-execute; got command %q", plan.Command)
	}
	if len(plan.ManualSteps) < 2 {
		t.Errorf("expected sudo apt-get steps; got %v", plan.ManualSteps)
	}
}

func TestPlanFix_LockfileFixWithKnownVersion(t *testing.T) {
	// Most common case: a project-lockfile finding with a known
	// in-major fix version. Result should be FixSemiSafe with an
	// ecosystem-appropriate upgrade command.
	f := findings.Finding{
		Detector: "osv-ioc", Name: "lodash", Version: "4.17.20",
		VulnID: "CVE-2021-23337", SourcePath: "/proj/package-lock.json",
		FixUpgradeTo: "4.17.21",
		References:   []string{"https://github.com/advisories/GHSA-..."},
	}
	plan, ok := PlanFix(f)
	if !ok || plan.Category != findings.FixSemiSafe {
		t.Fatalf("expected FixSemiSafe plan, got %+v ok=%v", plan, ok)
	}
	if plan.PackageName != "lodash" || plan.RequiredVersion != "4.17.21" {
		t.Errorf("dedup keys wrong: pkg=%q ver=%q", plan.PackageName, plan.RequiredVersion)
	}
	// ProjectDir comes from filepath.Dir(SourcePath), which is OS-native:
	// "/proj" on Unix, "\proj" on Windows. Compare portably.
	wantDir := filepath.FromSlash("/proj")
	if plan.ProjectDir != wantDir {
		t.Errorf("ProjectDir wrong: %q (want %q)", plan.ProjectDir, wantDir)
	}
	if plan.Command == "" {
		t.Error("expected non-empty command for npm lockfile fix")
	}
}

func TestPlanFix_NoInMajorFix_IsManual(t *testing.T) {
	// When OSV doesn't carry an in-major fix version, the only path
	// is a major upgrade — which can break peer deps. PlanFix
	// correctly downgrades to FixManual.
	f := findings.Finding{
		Detector: "osv-ioc", Name: "ancient-lib", Version: "1.2.3",
		VulnID: "GHSA-xxx", SourcePath: "/proj/package-lock.json",
		FixUpgradeTo: "", // no in-major fix
	}
	plan, ok := PlanFix(f)
	if !ok || plan.Category != findings.FixManual {
		t.Errorf("expected FixManual when no in-major fix, got cat=%v ok=%v", plan.Category, ok)
	}
	if plan.Command != "" {
		t.Errorf("FixManual must not auto-execute; got command %q", plan.Command)
	}
	if len(plan.ManualSteps) == 0 {
		t.Error("expected non-empty manual steps explaining major bump")
	}
}

func TestPlanFix_LockfileFix_AppendsAdvisoryURL(t *testing.T) {
	f := findings.Finding{
		Detector: "osv-ioc", Name: "lodash", Version: "4.17.20",
		VulnID: "CVE-X", SourcePath: "/proj/package-lock.json",
		FixUpgradeTo: "4.17.21",
		References:   []string{"https://advisory.example/CVE-X"},
	}
	plan, _ := PlanFix(f)
	found := false
	for _, step := range plan.ManualSteps {
		if strings.Contains(step, "https://advisory.example/CVE-X") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("advisory URL missing from manual steps: %v", plan.ManualSteps)
	}
}

func TestShellQuoteArg(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"lodash", "lodash"},
		{"foo bar", "'foo bar'"},
		{"foo'bar", `'foo'\''bar'`},
		{"@scope/pkg", "@scope/pkg"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := shellQuoteArg(c.in); got != c.want {
				t.Errorf("shellQuoteArg(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
