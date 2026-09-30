package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alessandro-bitetto/chaindora/internal/detectors/incident"
	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/incidents"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

const incidentIncompleteID = "CHDORA-INCIDENTS-INCOMPLETE"

// An explicit path must never silently fall back to another intelligence pack.
func scanIncidents(ctx context.Context, inv *inventory.Inventory, root, explicit string, excludes []string) ([]findings.Finding, error) {
	dir := explicit
	if dir == "" {
		home, _ := os.UserHomeDir()
		for _, candidate := range []string{"incidents", filepath.Join(home, ".chaindora", "incidents")} {
			info, err := os.Stat(candidate)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if !info.IsDir() {
				return nil, fmt.Errorf("incident pack %s is not a directory", candidate)
			}
			dir = candidate
			break
		}
	}
	if dir == "" {
		return nil, fmt.Errorf("no incident pack found; run chdora update, set --incidents, or explicitly use --skip-incidents")
	}
	pack, err := incidents.LoadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("load incident pack %s: %w", dir, err)
	}
	if len(pack) == 0 {
		return nil, fmt.Errorf("incident pack %s contains no incident records", dir)
	}
	return incident.New(pack, excludes...).Detect(ctx, inv, root)
}

func incidentCoverageFailure(root string, err error) findings.Finding {
	return findings.Finding{
		Detector: "incident-pack", Category: findings.CategoryConfiguration,
		Name: "incident-pack", VulnID: incidentIncompleteID,
		Severity: findings.SeverityLow, Confidence: findings.ConfidenceHigh,
		SourcePath: root, Summary: "Incident inspection incomplete: " + err.Error(),
	}
}
