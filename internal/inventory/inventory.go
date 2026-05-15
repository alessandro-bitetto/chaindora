package inventory

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// Ecosystem corresponds to OSV.dev ecosystem identifiers where applicable.
type Ecosystem string

const (
	EcosystemNPM     Ecosystem = "npm"
	EcosystemPyPI    Ecosystem = "PyPI"
	EcosystemActions Ecosystem = "GitHub Actions"
)

// Package represents one resolved dependency discovered in a manifest or lockfile.
type Package struct {
	Ecosystem  Ecosystem `json:"ecosystem"`
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	PURL       string    `json:"purl"`
	SourcePath string    `json:"source_path"`
	// Pinned reports whether a GitHub Actions ref is pinned to a 40-char SHA.
	// Zero value is meaningless for non-Actions ecosystems.
	Pinned bool `json:"pinned,omitempty"`
}

// Source identifies a manifest file that was successfully parsed.
type Source struct {
	Path      string    `json:"path"`
	Ecosystem Ecosystem `json:"ecosystem"`
	Kind      string    `json:"kind"`
}

// Inventory is the result of scanning a tree.
type Inventory struct {
	Packages []Package `json:"packages"`
	Sources  []Source  `json:"sources"`
	Errors   []string  `json:"errors,omitempty"`
}

// Scan walks root and parses any known lockfiles/manifests it finds.
func Scan(root string) (*Inventory, error) {
	inv := &Inventory{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			inv.Errors = append(inv.Errors, err.Error())
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "node_modules" || name == ".venv" || name == "venv" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		base := filepath.Base(path)
		switch base {
		case "package-lock.json":
			pkgs, perr := parseNPMPackageLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "package-lock.json "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemNPM, Kind: "package-lock.json"})
		case "requirements.txt":
			pkgs, perr := parsePipRequirements(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "requirements.txt "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemPyPI, Kind: "requirements.txt"})
		case "poetry.lock":
			pkgs, perr := parsePoetryLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "poetry.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemPyPI, Kind: "poetry.lock"})
		case "yarn.lock":
			pkgs, perr := parseYarnLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "yarn.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemNPM, Kind: "yarn.lock"})
		case "pnpm-lock.yaml":
			pkgs, perr := parsePnpmLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "pnpm-lock.yaml "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemNPM, Kind: "pnpm-lock.yaml"})
		case "uv.lock":
			pkgs, perr := parseUVLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "uv.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemPyPI, Kind: "uv.lock"})
		case "Pipfile.lock":
			pkgs, perr := parsePipfileLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "Pipfile.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemPyPI, Kind: "Pipfile.lock"})
		}

		// GitHub Actions workflows: any *.yml or *.yaml under .github/workflows/
		slashed := filepath.ToSlash(path)
		if strings.Contains(slashed, "/.github/workflows/") &&
			(strings.HasSuffix(slashed, ".yml") || strings.HasSuffix(slashed, ".yaml")) {
			pkgs, perr := parseGHActionsWorkflow(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "workflow "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemActions, Kind: "workflow"})
		}
		return nil
	})
	if err != nil {
		return inv, err
	}
	return inv, nil
}
