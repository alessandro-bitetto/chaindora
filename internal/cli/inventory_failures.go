package cli

import "github.com/alessandro-bitetto/chaindora/internal/findings"

// A failed parser or unreadable subtree is not evidence of a clean project.
// These findings make incomplete inventory visible in the existing JSON/SARIF
// formats; CI also refuses independently of severity, baseline and suppression.
func inventoryFailureFindings(root string, failures []string) []findings.Finding {
	var out []findings.Finding
	for _, failure := range failures {
		out = append(out, findings.Finding{
			Detector: "inventory", Category: findings.CategoryConfiguration,
			Name: "incomplete-inventory", VulnID: "CHDORA-INVENTORY-INCOMPLETE",
			Summary:  "Dependency inventory incomplete: " + failure,
			Severity: findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			SourcePath: root,
		})
	}
	return out
}
