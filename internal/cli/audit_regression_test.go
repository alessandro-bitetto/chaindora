package cli

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/detectors/osvioc"
	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
	"github.com/alessandro-bitetto/chaindora/internal/osv"
)

type auditRoundTrip func(*http.Request) (*http.Response, error)

func (f auditRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMalwareWithoutCVSSFailsDefaultCI(t *testing.T) {
	for _, hydrateFailure := range []bool{false, true} {
		client := osv.NewClient()
		client.HTTP = &http.Client{Transport: auditRoundTrip(func(r *http.Request) (*http.Response, error) {
			body := `{"id":"MAL-test-fixture","summary":"Inert test advisory"}`
			status := 200
			if strings.HasSuffix(r.URL.Path, "querybatch") {
				body = `{"results":[{"vulns":[{"id":"MAL-test-fixture"}]}]}`
			} else if hydrateFailure {
				status = 503
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}
		fs, err := osvioc.New(client).Detect(context.Background(), &inventory.Inventory{Packages: []inventory.Package{{Ecosystem: inventory.EcosystemNPM, Name: "fixture", Version: "1.0.0"}}})
		if err != nil || len(fs) != 1 {
			t.Fatalf("%+v %v", fs, err)
		}
		if fs[0].Severity != findings.SeverityCritical || !shouldFail(fs, "critical,high") {
			t.Fatalf("known malware passed CI: %+v", fs)
		}
	}
}

func TestMalformedGateConfigStopsBeforeProcessLookup(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(old); err != nil {
			t.Error(err)
		}
	})
	if err := os.WriteFile(filepath.Join(dir, "chaindora.yml"), []byte("deny: ["), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	for _, args := range [][]string{{"npm", "ci"}, {"--dry-run", "npm", "ci"}, {"--lenient", "--allow-offline", "npm", "ci"}} {
		err := gateExecCmd.RunE(gateExecCmd, args)
		if err == nil || !strings.Contains(err.Error(), "gate configuration") {
			t.Fatalf("ignored malformed config: %v", err)
		}
	}
	if err := gateCheckCmd.RunE(gateCheckCmd, []string{"fixture@1.0.0"}); err == nil || !strings.Contains(err.Error(), "gate configuration") {
		t.Fatalf("gate check ignored config: %v", err)
	}
}

func TestOperatorTokenFilePersistsAndRejectsSymlinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "read-token")
	first, err := loadServerReadToken(path, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadServerReadToken(path, true)
	if err != nil || first != second {
		t.Fatal("token changed across restart")
	}
	if len(first) != 64 {
		t.Fatal("unexpected token strength")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err == nil {
		if _, err := loadServerReadToken(link, false); err == nil {
			t.Fatal("accepted symlink")
		}
	}
}

func TestPredictiveFailureCannotBeSuppressedOrUpdateBaseline(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"node_modules/fixture":{"version":"1.0.0"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	baseline := filepath.Join(root, "baseline.json")
	original := []byte(`{"chdora_version":"fixture","fingerprints":[]}`)
	if err := os.WriteFile(baseline, original, 0600); err != nil {
		t.Fatal(err)
	}
	suppression := filepath.Join(root, "custom-policy.yml")
	if err := os.WriteFile(suppression, []byte("suppress:\n  - vuln_id: CHDORA-PREDICTIVE-INCOMPLETE\n    reason: attempted coverage bypass\n"), 0600); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(root, "report.sarif")
	settings := map[string]string{
		"skip-osv": "true", "skip-incidents": "true", "skip-heuristic": "true",
		"skip-predictive": "false", "skip-registry": "false", "offline": "false",
		"skip-integrity": "true", "fail-on": "none", "format": "json",
		"baseline": baseline, "update-baseline": "true", "suppress-file": suppression, "sarif": report,
	}
	for name, value := range settings {
		flag := ciCmd.Flags().Lookup(name)
		before, changed := flag.Value.String(), flag.Changed
		if err := ciCmd.Flags().Set(name, value); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = flag.Value.Set(before); flag.Changed = changed })
	}
	transport := http.DefaultTransport
	http.DefaultTransport = auditRoundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("fixture unavailable"))}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = transport })
	err := ciCmd.RunE(ciCmd, []string{root})
	exit, ok := err.(*ExitError)
	if !ok || exit.Code != 2 {
		t.Fatalf("incomplete predictor passed CI: %v", err)
	}
	after, err := os.ReadFile(baseline)
	if err != nil || string(after) != string(original) {
		t.Fatal("incomplete scan changed baseline")
	}
	data, err := os.ReadFile(report)
	if err != nil || !strings.Contains(string(data), "CHDORA-PREDICTIVE-INCOMPLETE") {
		t.Fatalf("coverage failure missing from report: %v", err)
	}
}
