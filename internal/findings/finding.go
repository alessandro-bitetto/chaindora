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

// Category classifies what kind of question a finding answers. Added in
// v0.7.0 to separate "we found a deliberate supply-chain attack against
// you" from "your dependency has a known CVE in legitimately-written
// code." These two things look identical in a Severity-only world but
// require different defenses, attention levels, and tools — and most of
// chdora's identity is in the first bucket. The renderer surfaces
// supply-chain findings prominently and collapses dependency-CVE
// findings into a secondary section.
type Category string

const (
	// CategorySupplyChainAttack — deliberate adversarial action:
	// malicious package versions (qix, Shai-Hulud, ultralytics), worm
	// file artifacts, dep-confusion-attack-shape, typosquat,
	// install-script-on-fresh-package. OSV.dev IDs starting with
	// "MAL-" land here, as do all incident-pack and most heuristic
	// findings.
	CategorySupplyChainAttack Category = "supply-chain-attack"

	// CategoryDependencyCVE — known security flaw in a legitimately-
	// authored dependency. OSV.dev IDs starting with "CVE-",
	// "GHSA-", "PYSEC-", etc. The honest-bug bucket.
	CategoryDependencyCVE Category = "dependency-cve"

	// CategoryHostForensics — post-compromise artifact on the local
	// machine: leaked credentials in dotfiles, modified shell rc,
	// persistence entries, ssh authorized-keys drift. Answers "did
	// I get hit?" rather than "could I be hit?".
	CategoryHostForensics Category = "host-forensics"

	// CategoryConfiguration — risk-shape configuration: unpinned
	// action refs, curl|bash in CI, etc. Not yet an attack but
	// reduces the cost of one happening to you.
	CategoryConfiguration Category = "configuration"

	// CategoryPredictive (v0.15+) — gate-style behavioral signals
	// replayed against already-installed packages. Not "known
	// malicious" (that's CategorySupplyChainAttack) and not "known
	// vulnerable" (that's CategoryDependencyCVE). Instead: this
	// installed version looks like an attack-in-progress shape —
	// published hours ago, publisher just changed, hash has shifted
	// since the version was last vetted, suspicious cross-version
	// drift. These are advisory by default (severity=medium) and
	// don't trip --fail-on=critical,high gates, but escalate to
	// critical when integrity-based signals fire (republish-guard
	// detecting a known name@version with different bytes).
	CategoryPredictive Category = "predictive"
)

// Finding is the normalized output of any detector. The shape is designed to
// map cleanly onto SARIF 2.1.0 results when the SARIF reporter lands in P3.
type Finding struct {
	Detector   string              `json:"detector"`
	Category   Category            `json:"category,omitempty"`
	PURL       string              `json:"purl"`
	Ecosystem  inventory.Ecosystem `json:"ecosystem"`
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	VulnID     string              `json:"vuln_id"`
	Summary    string              `json:"summary"`
	Severity   Severity            `json:"severity"`
	References []string            `json:"references,omitempty"`
	SourcePath string              `json:"source_path,omitempty"`
	// Integrity is the lockfile-recorded content hash for this
	// (name, version) pair when one is known. v0.15+. Carried on
	// findings so the v0.13 fleet server can detect cross-agent
	// divergence: if agent A reports lodash@4.17.21 with sha512-X
	// and agent B later reports the same with sha512-Y, the server
	// emits a fleet-level "republished" alert. Empty when the
	// originating ecosystem's lockfile doesn't expose it.
	Integrity string `json:"integrity,omitempty"`

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

// DeriveCategory returns the Category for a Finding. If Category is set
// explicitly (osv-ioc distinguishes MAL-* from CVE-*; incident-pack
// always sets SupplyChainAttack), that wins. Otherwise we infer from
// the Detector class so v0.7.0 doesn't have to touch every emit site
// in the host-forensics detector tree.
func DeriveCategory(f Finding) Category {
	if f.Category != "" {
		return f.Category
	}
	switch {
	case startsWith(f.Detector, "hostforensics:"):
		return CategoryHostForensics
	case f.Detector == "heuristic:unpinned-ref", f.Detector == "heuristic:ci-shell-pattern":
		return CategoryConfiguration
	case startsWith(f.Detector, "heuristic:"):
		return CategorySupplyChainAttack
	case f.Detector == "incident-pack":
		return CategorySupplyChainAttack
	case f.Detector == "osv-ioc":
		// Defensive — osvioc.go should have set this explicitly,
		// but if not, fall back to dep-cve which is the common case.
		return CategoryDependencyCVE
	case startsWith(f.Detector, "predictive:"):
		return CategoryPredictive
	}
	return ""
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
