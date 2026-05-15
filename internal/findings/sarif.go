package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	informationURI = "https://github.com/alessandro-bitetto/chaindora"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name,omitempty"`
	ShortDescription sarifMessage     `json:"shortDescription"`
	FullDescription  sarifMessage     `json:"fullDescription,omitempty"`
	HelpURI          string           `json:"helpUri,omitempty"`
	Properties       *sarifProperties `json:"properties,omitempty"`
}

type sarifProperties struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// EmitSARIF writes a SARIF 2.1.0 log to w. version identifies the chaindora
// build that produced the run.
func EmitSARIF(w io.Writer, fs []Finding, version string) error {
	rules := buildSARIFRules(fs)
	results := buildSARIFResults(fs)
	log := sarifLog{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "chaindora",
					InformationURI: informationURI,
					Version:        version,
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

func buildSARIFRules(fs []Finding) []sarifRule {
	seen := map[string]struct{}{}
	out := make([]sarifRule, 0, len(fs))
	for _, f := range fs {
		if _, ok := seen[f.VulnID]; ok {
			continue
		}
		seen[f.VulnID] = struct{}{}
		out = append(out, sarifRule{
			ID:               f.VulnID,
			Name:             f.VulnID,
			ShortDescription: sarifMessage{Text: truncForSARIF(f.Summary, 200)},
			FullDescription:  sarifMessage{Text: f.Summary},
			HelpURI:          firstNonEmpty(f.References),
			Properties: &sarifProperties{
				SecuritySeverity: severityScore(f.Severity),
				Tags:             []string{"supply-chain", "security", strings.ToLower(string(f.Ecosystem))},
			},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func buildSARIFResults(fs []Finding) []sarifResult {
	out := make([]sarifResult, 0, len(fs))
	for _, f := range fs {
		uri := f.SourcePath
		if uri == "" {
			uri = "chaindora:host-state"
		}
		out = append(out, sarifResult{
			RuleID:  f.VulnID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: fmt.Sprintf("%s %s — %s [%s]", f.Name, f.Version, f.Summary, f.Detector)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: uri},
				},
			}},
			PartialFingerprints: map[string]string{
				"primaryLocationLineHash": fingerprint(f),
			},
		})
	}
	return out
}

func sarifLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	case SeverityLow:
		return "note"
	}
	return "note"
}

// severityScore returns a representative CVSS score for GitHub code-scanning's
// security-severity property. We pick a middle value within each bucket; the
// exact number is only used by GitHub to bucket and sort.
func severityScore(s Severity) string {
	switch s {
	case SeverityCritical:
		return "9.8"
	case SeverityHigh:
		return "8.0"
	case SeverityMedium:
		return "5.5"
	case SeverityLow:
		return "3.0"
	}
	return "0.0"
}

func firstNonEmpty(refs []string) string {
	for _, r := range refs {
		if r != "" {
			return r
		}
	}
	return ""
}

func fingerprint(f Finding) string {
	h := sha256.Sum256([]byte(f.Detector + "|" + f.VulnID + "|" + f.PURL + "|" + f.SourcePath))
	return hex.EncodeToString(h[:])
}

func truncForSARIF(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
