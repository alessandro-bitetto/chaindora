package gate

import (
	"regexp"
	"strings"
)

var (
	jsBulkEnvironment = regexp.MustCompile(`JSON\s*\.\s*stringify\s*\(\s*process\s*\.\s*env\s*\)`)
	pyBulkEnvironment = regexp.MustCompile(`(?:dict\s*\(\s*os\.environ\s*\)|(?:json\.dumps|urlencode)\s*\(\s*(?:dict\s*\(\s*)?os\.environ\b|os\.environ\.(?:copy|items)\s*\()`)
	jsOutbound        = regexp.MustCompile(`\b(?:fetch\s*\(|(?:axios|https?|request)\s*\.\s*(?:post|put|request|get)\s*\()`)
	pyOutbound        = regexp.MustCompile(`\b(?:(?:requests|httpx)\.(?:post|put|request|get)\s*\(|(?:urllib\.request\.)?(?:urlopen|Request)\s*\()`)
	credentialPath    = regexp.MustCompile(`(?i)(?:\.npmrc\b|\.pypirc\b|\.aws[/\\]+credentials\b|\.ssh[/\\]+id_(?:rsa|ed25519|ecdsa)\b)`)
	jsFileRead        = regexp.MustCompile(`\b(?:readFileSync|readFile|createReadStream)\s*\(`)
	pyFileRead        = regexp.MustCompile(`\b(?:open|read_text|read_bytes)\s*\(`)
)

// DetectCredentialExfiltration reports combinations of secret collection and
// outbound traffic in JS/TS and Python source. These are reviewable heuristics,
// not data-flow proofs. Reading an individual environment variable or making
// a network call alone never triggers a finding. Evidence excludes source
// snippets so a report cannot copy credentials embedded in the input.
func DetectCredentialExfiltration(path string, content []byte) []StaticFinding {
	var bulk, outbound, read *regexp.Regexp
	switch {
	case isJSish(path):
		bulk, outbound, read = jsBulkEnvironment, jsOutbound, jsFileRead
	case strings.HasSuffix(path, ".py"):
		bulk, outbound, read = pyBulkEnvironment, pyOutbound, pyFileRead
	default:
		return nil
	}
	if !outbound.Match(content) {
		return nil
	}
	var hits []StaticFinding
	if bulk.Match(content) {
		hits = append(hits, StaticFinding{
			Pattern: "env-var-exfil-shape", Path: path, Weight: 3,
			Snippet: "bulk environment serialization and outbound HTTP calls in the same file; review for secret exfiltration",
		})
	}
	if credentialPath.Match(content) && read.Match(content) {
		hits = append(hits, StaticFinding{
			Pattern: "credential-file-exfil-shape", Path: path, Weight: 3,
			Snippet: "credential-file references, file reads and outbound HTTP calls in the same file; review for credential theft",
		})
	}
	return hits
}

func credentialFindings(fs []StaticFinding) []StaticFinding {
	var out []StaticFinding
	for _, f := range fs {
		if f.Pattern == "env-var-exfil-shape" || f.Pattern == "credential-file-exfil-shape" {
			out = append(out, f)
		}
	}
	return out
}
