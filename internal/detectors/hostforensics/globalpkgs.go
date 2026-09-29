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
//   - npm   (`npm ls -g --json --depth=0`)        → EcosystemNPM
//   - pip   (`pip list --format=json`, pip3 fallback) → EcosystemPyPI
//   - brew  (`brew list --formula --versions`)    → EcosystemHomebrew
//   - apt   (`dpkg-query -W -f='${Package}|${Version}\n'`) → EcosystemDebian
//
// OSV.dev queries only the first two (npm + PyPI); brew and apt go through
// the incident-pack matcher (and future heuristics) since OSV doesn't expose
// those ecosystems in the same way.
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
	if hasBinary("brew") {
		if data, err := exec.Command("brew", "list", "--formula", "--versions").Output(); err == nil {
			if pkgs := parseBrewOutput(data); len(pkgs) > 0 {
				inv.Packages = append(inv.Packages, pkgs...)
				inv.Sources = append(inv.Sources, inventory.Source{
					Path:      "brew:global",
					Ecosystem: inventory.EcosystemHomebrew,
					Kind:      "brew-global",
				})
			}
		}
	}
	if hasBinary("dpkg-query") {
		if data, err := exec.Command("dpkg-query", "-W", "-f=${Package}|${Version}\n").Output(); err == nil {
			if pkgs := parseDpkgOutput(data); len(pkgs) > 0 {
				inv.Packages = append(inv.Packages, pkgs...)
				inv.Sources = append(inv.Sources, inventory.Source{
					Path:      "dpkg:global",
					Ecosystem: inventory.EcosystemDebian,
					Kind:      "apt-global",
				})
			}
		}
	}
	return inv
}

// parseBrewOutput parses output of `brew list --formula --versions`:
//
//   git 2.45.0
//   go 1.22.3
//   sqlite 3.45.3
//
// The first token is the formula name; the rest are space-joined as a
// version (Homebrew can install multiple versions side-by-side).
func parseBrewOutput(data []byte) []inventory.Package {
	var out []inventory.Package
	for _, line := range splitLines(data) {
		fields := splitFields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		version := joinSpace(fields[1:])
		out = append(out, inventory.Package{
			Ecosystem:  inventory.EcosystemHomebrew,
			Name:       name,
			Version:    version,
			PURL:       inventory.PURL(inventory.EcosystemHomebrew, name, version),
			SourcePath: "brew:global",
		})
	}
	return out
}

// parseDpkgOutput parses pipe-delimited dpkg-query output:
//
//   adduser|3.118
//   apt|2.4.13
//   bash|5.1-6ubuntu1.1
func parseDpkgOutput(data []byte) []inventory.Package {
	var out []inventory.Package
	for _, line := range splitLines(data) {
		idx := indexByte(line, '|')
		if idx <= 0 {
			continue
		}
		name := line[:idx]
		version := line[idx+1:]
		if name == "" || version == "" {
			continue
		}
		out = append(out, inventory.Package{
			Ecosystem:  inventory.EcosystemDebian,
			Name:       name,
			Version:    version,
			PURL:       inventory.PURL(inventory.EcosystemDebian, name, version),
			SourcePath: "dpkg:global",
		})
	}
	return out
}

// Small helpers avoid pulling strings into a tight hot loop just for splits.
func splitLines(b []byte) []string {
	s := string(b)
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				out = append(out, trim(s[start:i]))
			} else if start < i {
				out = append(out, "")
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, trim(s[start:]))
	}
	return out
}

func splitFields(s string) []string {
	var out []string
	start := -1
	for i, c := range s {
		if c == ' ' || c == '\t' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

func joinSpace(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += " " + p
	}
	return out
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func trim(s string) string {
	a, b := 0, len(s)
	for a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r') {
		a++
	}
	for b > a && (s[b-1] == ' ' || s[b-1] == '\t' || s[b-1] == '\r') {
		b--
	}
	return s[a:b]
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
