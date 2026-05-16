package gate

import (
	"context"
	"fmt"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/osv"
)

// OSVCheck queries OSV.dev for the requested (ecosystem, name,
// version) and blocks the install if the package is in the OpenSSF
// Malicious Packages feed (records with MAL-* IDs). Regular CVE
// matches (GHSA-*, CVE-*) downgrade to Warn — the user can still
// install with --allow-warn, since the gate isn't a CVE policy
// engine and many CVE'd packages are still useful with mitigations.
//
// Network failure → Verdict=Unknown (fail-closed policy converts
// to Block by default).
type OSVCheck struct {
	Client osvClient
}

// osvClient is the subset of osv.Client we depend on. Defined as
// an interface so tests can inject deterministic responses.
type osvClient interface {
	QueryBatch(ctx context.Context, queries []osv.Query) ([]osv.QueryResult, error)
}

// NewOSVCheck returns an OSVCheck backed by the public OSV.dev
// service. Tests should construct OSVCheck{Client: fake} directly.
func NewOSVCheck() *OSVCheck {
	return &OSVCheck{Client: osv.NewClient()}
}

func (o *OSVCheck) Name() string { return "osv-malicious" }

func (o *OSVCheck) Check(ctx context.Context, ref PackageRef) CheckResult {
	result := CheckResult{Checker: o.Name()}
	if ref.Ecosystem == "git" {
		// Git-URL packages aren't OSV-cataloged (OSV's unit is a
		// registry package). The git-url checker handles their
		// trust evaluation; OSV passes through.
		result.Verdict = VerdictApprove
		result.Reason = "osv: git-URL deps not registry-cataloged"
		return result
	}
	ecosystem := mapEcosystemToOSV(ref.Ecosystem)
	if ecosystem == "" {
		result.Verdict = VerdictUnknown
		result.Reason = fmt.Sprintf("OSV does not catalog ecosystem %q", ref.Ecosystem)
		return result
	}
	queries := []osv.Query{{
		Package: osv.QueryPackage{Name: ref.Name, Ecosystem: ecosystem},
		Version: ref.Version,
	}}
	results, err := o.Client.QueryBatch(ctx, queries)
	if err != nil {
		result.Verdict = VerdictUnknown
		result.Reason = fmt.Sprintf("OSV query failed: %v", err)
		return result
	}
	if len(results) == 0 || len(results[0].Vulns) == 0 {
		result.Verdict = VerdictApprove
		result.Reason = "no entries in OSV / OpenSSF Malicious Packages feed"
		return result
	}
	// Partition matches: MAL-* are blocking, others are warnings.
	var malicious, cves []string
	for _, v := range results[0].Vulns {
		if strings.HasPrefix(v.ID, "MAL-") {
			malicious = append(malicious, v.ID)
		} else {
			cves = append(cves, v.ID)
		}
	}
	if len(malicious) > 0 {
		result.Verdict = VerdictBlock
		result.Reason = fmt.Sprintf("listed in OpenSSF Malicious Packages: %s", strings.Join(malicious, ", "))
		if len(cves) > 0 {
			result.Detail = fmt.Sprintf("also has %d CVE match(es): %s", len(cves), strings.Join(cves, ", "))
		}
		return result
	}
	// No MAL-*, but real CVEs — warn the user. The default Strict
	// policy still blocks here; Lenient lets it through. Either
	// way the user knows the package has CVE history at this version.
	result.Verdict = VerdictWarn
	result.Reason = fmt.Sprintf("has %d known CVE(s) at this version: %s", len(cves), strings.Join(cves, ", "))
	return result
}

// mapEcosystemToOSV converts the gate's ecosystem strings to the
// values OSV expects. Empty return means "not supported by OSV
// public API" (Homebrew, browser extensions, custom ecosystems).
func mapEcosystemToOSV(eco string) string {
	switch eco {
	case "npm":
		return "npm"
	case "pypi", "pip":
		return "PyPI"
	case "go", "golang":
		return "Go"
	case "rubygems":
		return "RubyGems"
	case "crates", "cargo":
		return "crates.io"
	case "maven":
		return "Maven"
	case "nuget":
		return "NuGet"
	case "packagist", "composer":
		return "Packagist"
	case "swift":
		return "SwiftURL"
	case "pub":
		return "Pub"
	case "hex":
		return "Hex"
	case "hackage":
		return "Hackage"
	case "cran":
		return "CRAN"
	}
	return ""
}
