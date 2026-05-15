package heuristic

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

type ciShellPattern struct {
	Pattern *regexp.Regexp
	VulnID  string
	Summary string
}

var ciShellPatterns = []ciShellPattern{
	{
		Pattern: regexp.MustCompile(`curl[^|]+\|\s*(bash|sh|zsh)\b`),
		VulnID:  "HEUR-CI-CURL-PIPE",
		Summary: "CI script pipes curl output directly into a shell — common malware delivery pattern",
	},
	{
		Pattern: regexp.MustCompile(`wget[^|]+\|\s*(bash|sh|zsh)\b`),
		VulnID:  "HEUR-CI-WGET-PIPE",
		Summary: "CI script pipes wget output directly into a shell — common malware delivery pattern",
	},
	{
		Pattern: regexp.MustCompile(`eval\s+["']?\$\(\s*base64\s+(-d|--decode)`),
		VulnID:  "HEUR-CI-EVAL-BASE64",
		Summary: "CI script evals a base64-decoded payload — strong indicator of obfuscation",
	},
	{
		Pattern: regexp.MustCompile(`eval\s+["']?\$\(\s*curl`),
		VulnID:  "HEUR-CI-EVAL-CURL",
		Summary: "CI script evals output of a network call",
	},
}

// detectCIShellPatterns walks every CI YAML file in the inventory's Sources
// and scans `script:` / `run:` / `commands:` blocks for suspicious patterns.
func detectCIShellPatterns(inv *inventory.Inventory) []findings.Finding {
	if inv == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []findings.Finding
	for _, src := range inv.Sources {
		if !isCIYAMLSource(src.Ecosystem) {
			continue
		}
		if seen[src.Path] {
			continue
		}
		seen[src.Path] = true
		out = append(out, scanCIShellFile(src.Path)...)
	}
	return out
}

func isCIYAMLSource(e inventory.Ecosystem) bool {
	switch e {
	case inventory.EcosystemActions,
		inventory.EcosystemGitLabCI,
		inventory.EcosystemBitbucketPipes,
		inventory.EcosystemCircleCIOrbs,
		inventory.EcosystemAzurePipelines:
		return true
	}
	return false
}

func scanCIShellFile(path string) []findings.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil
	}
	var out []findings.Finding
	walkScriptNodes(&root, func(line string, lineNo int) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			return
		}
		for _, p := range ciShellPatterns {
			if p.Pattern.MatchString(line) {
				out = append(out, findings.Finding{
					Detector:   "heuristic:ci-shell-pattern",
					VulnID:     p.VulnID,
					Summary:    fmt.Sprintf("%s (line %d: %q)", p.Summary, lineNo, truncate(trimmed, 120)),
					Severity:   findings.SeverityHigh,
					SourcePath: path,
				})
			}
		}
	})
	return out
}

var scriptKeys = map[string]bool{
	"script":        true,
	"run":           true,
	"commands":      true,
	"before_script": true,
	"after_script":  true,
}

// walkScriptNodes finds every mapping key whose name is in scriptKeys and
// calls emit for each line of its scalar/sequence value, with an approximate
// line number from the YAML source.
func walkScriptNodes(node *yaml.Node, emit func(line string, lineNo int)) {
	if node == nil {
		return
	}
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range node.Content {
			walkScriptNodes(c, emit)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			val := node.Content[i+1]
			if key.Kind == yaml.ScalarNode && scriptKeys[strings.ToLower(key.Value)] {
				emitFromShellValue(val, emit)
				continue
			}
			walkScriptNodes(val, emit)
		}
	}
}

func emitFromShellValue(val *yaml.Node, emit func(string, int)) {
	if val == nil {
		return
	}
	switch val.Kind {
	case yaml.ScalarNode:
		for i, line := range strings.Split(val.Value, "\n") {
			emit(line, val.Line+i)
		}
	case yaml.SequenceNode:
		for _, item := range val.Content {
			if item.Kind == yaml.ScalarNode {
				for i, line := range strings.Split(item.Value, "\n") {
					emit(line, item.Line+i)
				}
			}
		}
	}
}
