package hostforensics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// ScanExtensions enumerates installed browser extensions (Chromium-based:
// Chrome, Edge, Brave, Vivaldi) and IDE extensions (VSCode + Cursor + the
// VSCode Server) and returns them as an inventory.Inventory. Each entry
// flows through the existing detector pipeline; incident-pack entries can
// target specific extension IDs the same way they target npm packages today.
//
// No bad-extension list is shipped yet — `chdora update`'s incident pack
// will grow extension-targeted entries in follow-ups.
func ScanExtensions(home string) *inventory.Inventory {
	inv := &inventory.Inventory{}
	if pkgs := scanChromiumExtensions(home); len(pkgs) > 0 {
		inv.Packages = append(inv.Packages, pkgs...)
		inv.Sources = append(inv.Sources, inventory.Source{
			Path:      "browser-extensions",
			Ecosystem: inventory.EcosystemBrowserExt,
			Kind:      "chromium-extensions",
		})
	}
	if pkgs := scanVSCodeExtensions(home); len(pkgs) > 0 {
		inv.Packages = append(inv.Packages, pkgs...)
		inv.Sources = append(inv.Sources, inventory.Source{
			Path:      "ide-extensions",
			Ecosystem: inventory.EcosystemIDEExt,
			Kind:      "vscode-cursor-extensions",
		})
	}
	return inv
}

// ---- Chromium-based browsers ----

func chromiumExtensionRoots(home string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			filepath.Join(home, "Library", "Application Support", "Google", "Chrome"),
			filepath.Join(home, "Library", "Application Support", "Microsoft Edge"),
			filepath.Join(home, "Library", "Application Support", "BraveSoftware", "Brave-Browser"),
			filepath.Join(home, "Library", "Application Support", "Vivaldi"),
			filepath.Join(home, "Library", "Application Support", "Arc", "User Data"),
		}
	case "linux":
		return []string{
			filepath.Join(home, ".config", "google-chrome"),
			filepath.Join(home, ".config", "microsoft-edge"),
			filepath.Join(home, ".config", "BraveSoftware", "Brave-Browser"),
			filepath.Join(home, ".config", "vivaldi"),
			filepath.Join(home, ".config", "chromium"),
		}
	case "windows":
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			local = filepath.Join(home, "AppData", "Local")
		}
		return []string{
			filepath.Join(local, "Google", "Chrome", "User Data"),
			filepath.Join(local, "Microsoft", "Edge", "User Data"),
			filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data"),
			filepath.Join(local, "Vivaldi", "User Data"),
		}
	}
	return nil
}

// scanChromiumExtensions walks <root>/<Profile>/Extensions/<ID>/<version>/manifest.json
// for every Chromium-based browser profile under each root. Returns a Package
// per (extension-id, version), deduplicated across profiles.
func scanChromiumExtensions(home string) []inventory.Package {
	var pkgs []inventory.Package
	seen := map[string]struct{}{}
	for _, root := range chromiumExtensionRoots(home) {
		profiles, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, p := range profiles {
			if !p.IsDir() {
				continue
			}
			// Profile dir names: "Default", "Profile 1", "Profile 2", ...
			extDir := filepath.Join(root, p.Name(), "Extensions")
			extIDs, err := os.ReadDir(extDir)
			if err != nil {
				continue
			}
			for _, id := range extIDs {
				if !id.IsDir() {
					continue
				}
				// 32-char alphabetic IDs are the standard; we don't filter
				// strictly in case of dev-mode-loaded extensions.
				versionDirs, err := os.ReadDir(filepath.Join(extDir, id.Name()))
				if err != nil {
					continue
				}
				for _, v := range versionDirs {
					if !v.IsDir() {
						continue
					}
					manifest := filepath.Join(extDir, id.Name(), v.Name(), "manifest.json")
					data, err := os.ReadFile(manifest)
					if err != nil {
						continue
					}
					var m struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					}
					_ = json.Unmarshal(data, &m)
					version := m.Version
					if version == "" {
						version = v.Name()
					}
					key := id.Name() + "@" + version
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					pkgs = append(pkgs, inventory.Package{
						Ecosystem:  inventory.EcosystemBrowserExt,
						Name:       id.Name(),
						Version:    version,
						PURL:       inventory.PURL(inventory.EcosystemBrowserExt, id.Name(), version),
						SourcePath: manifest,
					})
				}
			}
		}
	}
	return pkgs
}

// ---- VSCode + Cursor + VSCode Server ----

func vscodeExtensionRoots(home string) []string {
	return []string{
		filepath.Join(home, ".vscode", "extensions"),
		filepath.Join(home, ".vscode-server", "extensions"),
		filepath.Join(home, ".cursor", "extensions"),
	}
}

// scanVSCodeExtensions enumerates flat-layout VSCode-family extensions. Each
// directory is named `publisher.name-version`. We split on the LAST '-' to
// separate the version (semver may contain dots and dashes — pre-release
// suffixes — but the convention is the version sits at the tail). When a
// package.json is present we prefer its canonical Publisher.Name + Version
// over the directory parse.
func scanVSCodeExtensions(home string) []inventory.Package {
	var pkgs []inventory.Package
	seen := map[string]struct{}{}
	for _, root := range vscodeExtensionRoots(home) {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			idx := strings.LastIndex(name, "-")
			if idx <= 0 {
				continue
			}
			id := name[:idx]
			version := name[idx+1:]
			pkgJSON := filepath.Join(root, name, "package.json")
			if data, err := os.ReadFile(pkgJSON); err == nil {
				var m struct {
					Name      string `json:"name"`
					Version   string `json:"version"`
					Publisher string `json:"publisher"`
				}
				if err := json.Unmarshal(data, &m); err == nil {
					if m.Version != "" {
						version = m.Version
					}
					if m.Publisher != "" && m.Name != "" {
						id = m.Publisher + "." + m.Name
					}
				}
			}
			key := id + "@" + version
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			pkgs = append(pkgs, inventory.Package{
				Ecosystem:  inventory.EcosystemIDEExt,
				Name:       id,
				Version:    version,
				PURL:       inventory.PURL(inventory.EcosystemIDEExt, id, version),
				SourcePath: filepath.Join(root, name),
			})
		}
	}
	return pkgs
}
