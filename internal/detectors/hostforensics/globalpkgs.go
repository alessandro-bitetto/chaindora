package hostforensics

import (
	"encoding/json"
	"os/exec"

	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// ScanGlobalPackages enumerates globally-installed packages via the system's
// package managers and returns them as an Inventory. Each manager is silently
// skipped if its binary isn't on PATH. Currently covers:
//
//   - npm   (`npm ls -g --json --depth=0`)
//   - pip   (`pip list --format=json`, falling back to `pip3`)
//
// Homebrew and apt are intentionally out of scope until OSV.dev catalogs them
// or we add separate Ecosystem constants and curated incident entries for
// those package managers.
func ScanGlobalPackages() *inventory.Inventory {
	inv := &inventory.Inventory{}
	if hasBinary("npm") {
		if data, err := exec.Command("npm", "ls", "-g", "--json", "--depth=0").Output(); len(data) > 0 || err == nil {
			if pkgs, perr := parseNPMGlobalOutput(data); perr == nil && len(pkgs) > 0 {
				inv.Packages = append(inv.Packages, pkgs...)
				inv.Sources = append(inv.Sources, inventory.Source{
					Path:      "npm:global",
					Ecosystem: inventory.EcosystemNPM,
					Kind:      "npm-global",
				})
			}
		}
	}
	pipBin := ""
	if hasBinary("pip") {
		pipBin = "pip"
	} else if hasBinary("pip3") {
		pipBin = "pip3"
	}
	if pipBin != "" {
		if data, err := exec.Command(pipBin, "list", "--format=json").Output(); err == nil {
			if pkgs, perr := parsePipGlobalOutput(data); perr == nil && len(pkgs) > 0 {
				inv.Packages = append(inv.Packages, pkgs...)
				inv.Sources = append(inv.Sources, inventory.Source{
					Path:      pipBin + ":global",
					Ecosystem: inventory.EcosystemPyPI,
					Kind:      "pip-global",
				})
			}
		}
	}
	return inv
}

func hasBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// parseNPMGlobalOutput parses the JSON tree produced by
// `npm ls -g --json --depth=0`. npm exits non-zero when peer-deps are missing
// but still emits valid JSON, so we try to parse regardless of exit code as
// long as some bytes came back.
func parseNPMGlobalOutput(data []byte) ([]inventory.Package, error) {
	var doc struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make([]inventory.Package, 0, len(doc.Dependencies))
	for name, info := range doc.Dependencies {
		if info.Version == "" {
			continue
		}
		out = append(out, inventory.Package{
			Ecosystem:  inventory.EcosystemNPM,
			Name:       name,
			Version:    info.Version,
			PURL:       inventory.PURL(inventory.EcosystemNPM, name, info.Version),
			SourcePath: "npm:global",
		})
	}
	return out, nil
}

// parsePipGlobalOutput parses the JSON array produced by
// `pip list --format=json`.
func parsePipGlobalOutput(data []byte) ([]inventory.Package, error) {
	var items []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, err
	}
	out := make([]inventory.Package, 0, len(items))
	for _, item := range items {
		if item.Name == "" || item.Version == "" {
			continue
		}
		name := inventory.NormalizePyPIName(item.Name)
		out = append(out, inventory.Package{
			Ecosystem:  inventory.EcosystemPyPI,
			Name:       name,
			Version:    item.Version,
			PURL:       inventory.PURL(inventory.EcosystemPyPI, name, item.Version),
			SourcePath: "pip:global",
		})
	}
	return out, nil
}
