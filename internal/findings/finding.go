package findings

import "github.com/alessandro-bitetto/chaindora/internal/inventory"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityUnknown  Severity = "UNKNOWN"
)

// Finding is the normalized output of any detector. The shape is designed to
// map cleanly onto SARIF 2.1.0 results when the SARIF reporter lands in P3.
type Finding struct {
	Detector   string              `json:"detector"`
	PURL       string              `json:"purl"`
	Ecosystem  inventory.Ecosystem `json:"ecosystem"`
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	VulnID     string              `json:"vuln_id"`
	Summary    string              `json:"summary"`
	Severity   Severity            `json:"severity"`
	References []string            `json:"references,omitempty"`
	SourcePath string              `json:"source_path,omitempty"`

	// FixUpgradeTo, when set, names a known-clean version of Name that the
	// fix layer should propose pinning to (e.g. "5.6.2" for chalk). Set by
	// the incident-pack detector from the YAML's packages[].safe_version.
	FixUpgradeTo string `json:"fix_upgrade_to,omitempty"`
	// PostCompromise is a list of additional manual steps the detector
	// wants surfaced at fix time — typically credential-rotation actions
	// the user must take by hand. Set by the incident-pack detector from
	// the YAML's top-level post_compromise list.
	PostCompromise []string `json:"post_compromise,omitempty"`
}
