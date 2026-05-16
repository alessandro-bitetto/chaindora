package integrity

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// checkCargoLockfileVsDisk verifies that crates pinned in Cargo.lock
// actually exist in the cargo registry cache. Walks every
// `~/.cargo/registry/src/*/` directory looking for `<name>-<version>/`
// dirs matching what the lockfile pins. A missing dir alone isn't
// proof of tampering (a fresh checkout where `cargo build` hasn't
// run yet has no cache), but a MISMATCHED dir — say
// `~/.cargo/registry/src/.../serde-1.0.50/` when the lockfile pins
// 1.0.100 — is a hard drift signal.
//
// We deliberately do NOT recompute the .crate sha256 here. Cargo
// already does that on `cargo build`; chdora's value-add is finding
// silently-divergent state, not duplicating cargo's own checks.
func (d *Detector) checkCargoLockfileVsDisk(ctx context.Context, lockPath string) []findings.Finding {
	pkgs, err := inventory.ParseCargoLock(lockPath)
	if err != nil || len(pkgs) == 0 {
		return nil
	}
	cargoSrc := cargoRegistrySrcDirs()
	if len(cargoSrc) == 0 {
		return nil
	}
	// Build a name → set-of-on-disk-versions index.
	onDisk := map[string]map[string]struct{}{}
	for _, root := range cargoSrc {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			// "name-version" form, with name potentially containing hyphens.
			n := e.Name()
			// Last hyphen with what follows starting with a digit is version.
			for i := len(n) - 1; i > 0; i-- {
				if n[i] == '-' && i+1 < len(n) && n[i+1] >= '0' && n[i+1] <= '9' {
					name := n[:i]
					ver := n[i+1:]
					if onDisk[name] == nil {
						onDisk[name] = map[string]struct{}{}
					}
					onDisk[name][ver] = struct{}{}
					break
				}
			}
		}
	}
	var out []findings.Finding
	for _, p := range pkgs {
		versions, ok := onDisk[p.Name]
		if !ok {
			continue // crate not cached locally — not a drift signal
		}
		if _, exact := versions[p.Version]; exact {
			continue
		}
		// Has cached versions of this crate, but not the one
		// Cargo.lock pins. The on-disk versions could be from a
		// different project; we surface this as a soft (medium)
		// signal, not critical, because false positives are easy.
		ondiskList := make([]string, 0, len(versions))
		for v := range versions {
			ondiskList = append(ondiskList, v)
		}
		out = append(out, findings.Finding{
			Detector:  "integrity:cargo-lockfile-vs-disk",
			Category:  findings.CategoryHostForensics,
			Ecosystem: inventory.EcosystemCrates,
			Name:      p.Name,
			Version:   p.Version,
			PURL:      p.PURL,
			VulnID:    "INTEGRITY-DRIFT-CARGO",
			Summary: fmt.Sprintf(
				"Cargo.lock pins %s@%s but ~/.cargo/registry/src/ has %s instead (no match for pinned version)",
				p.Name, p.Version, strings.Join(ondiskList, ", ")),
			Severity:   findings.SeverityMedium,
			SourcePath: lockPath,
		})
	}
	return out
}

func cargoRegistrySrcDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	registry := filepath.Join(home, ".cargo", "registry", "src")
	entries, err := os.ReadDir(registry)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, filepath.Join(registry, e.Name()))
		}
	}
	return out
}

// checkGoModulesLockfileVsDisk verifies modules in go.sum exist in
// ~/go/pkg/mod/. Same logic as cargo: a MISMATCHED-version directory
// for a module the lockfile pins is the signal.
func (d *Detector) checkGoModulesLockfileVsDisk(ctx context.Context, sumPath string) []findings.Finding {
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		gopath = filepath.Join(home, "go")
	}
	modRoot := filepath.Join(gopath, "pkg", "mod")
	if _, err := os.Stat(modRoot); err != nil {
		return nil
	}
	f, err := os.Open(sumPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []findings.Finding
	seen := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 3 || strings.HasSuffix(fields[1], "/go.mod") {
			continue
		}
		module, version := fields[0], fields[1]
		key := module + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		// Go's module cache stores at <gopath>/pkg/mod/<escaped-module>@<version>/.
		// Escaping replaces uppercase letters with !lowercase — github.com/Foo/Bar
		// becomes github.com/!foo/!bar. Approximate by checking if any
		// matching dir exists.
		parent := filepath.Join(modRoot, filepath.FromSlash(escapeGoModulePath(module)))
		parentDir := filepath.Dir(parent)
		base := filepath.Base(parent) + "@" + version
		if _, err := os.Stat(filepath.Join(parentDir, base)); err == nil {
			continue
		}
		// Check if SOME version of the module is cached but with a
		// different version. That's the drift signal.
		entries, _ := os.ReadDir(parentDir)
		other := []string{}
		basePrefix := filepath.Base(parent) + "@"
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), basePrefix) {
				other = append(other, strings.TrimPrefix(e.Name(), basePrefix))
			}
		}
		if len(other) == 0 {
			continue // module not cached at all — not a drift signal
		}
		out = append(out, findings.Finding{
			Detector:  "integrity:gomod-lockfile-vs-disk",
			Category:  findings.CategoryHostForensics,
			Ecosystem: inventory.EcosystemGoModules,
			Name:      module,
			Version:   version,
			PURL:      inventory.PURL(inventory.EcosystemGoModules, module, version),
			VulnID:    "INTEGRITY-DRIFT-GOMOD",
			Summary: fmt.Sprintf(
				"go.sum pins %s@%s but $GOPATH/pkg/mod/ has %s instead",
				module, version, strings.Join(other, ", ")),
			Severity:   findings.SeverityMedium,
			SourcePath: sumPath,
		})
	}
	return out
}

// escapeGoModulePath approximates the Go module cache's path
// encoding: uppercase letters → !lowercase. Good enough for the
// "does this directory exist" check.
func escapeGoModulePath(p string) string {
	var b strings.Builder
	for _, c := range p {
		if c >= 'A' && c <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(c + ('a' - 'A'))
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// checkPipLockfileVsDisk compares Pipfile.lock pinned versions
// against installed site-packages metadata. Walks the active
// virtualenv (if any) and checks `<name>-<version>.dist-info/`
// directories. Reports drift when the lockfile pin doesn't match
// what's installed.
func (d *Detector) checkPipLockfileVsDisk(ctx context.Context, lockPath string) []findings.Finding {
	sitePackages := findPipSitePackages(filepath.Dir(lockPath))
	if sitePackages == "" {
		return nil
	}
	pkgs, err := inventory.ParsePipfileLock(lockPath)
	if err != nil {
		return nil
	}
	installed := readSitePackagesVersions(sitePackages)
	var out []findings.Finding
	for _, p := range pkgs {
		v, ok := installed[strings.ToLower(p.Name)]
		if !ok {
			continue
		}
		if v == p.Version {
			continue
		}
		out = append(out, findings.Finding{
			Detector:  "integrity:pip-lockfile-vs-disk",
			Category:  findings.CategoryHostForensics,
			Ecosystem: inventory.EcosystemPyPI,
			Name:      p.Name,
			Version:   p.Version,
			PURL:      p.PURL,
			VulnID:    "INTEGRITY-DRIFT-PIP",
			Summary: fmt.Sprintf(
				"Pipfile.lock pins %s==%s but site-packages reports %s",
				p.Name, p.Version, v),
			Severity:   findings.SeverityMedium,
			SourcePath: lockPath,
		})
	}
	return out
}

// findPipSitePackages looks for the closest virtualenv site-
// packages directory relative to projectDir. Checks `.venv` and
// `venv` (the two common names), then any `lib/python*/site-
// packages` underneath them.
func findPipSitePackages(projectDir string) string {
	for _, venvName := range []string{".venv", "venv", "env"} {
		venv := filepath.Join(projectDir, venvName)
		lib := filepath.Join(venv, "lib")
		entries, err := os.ReadDir(lib)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), "python") {
				sp := filepath.Join(lib, e.Name(), "site-packages")
				if _, err := os.Stat(sp); err == nil {
					return sp
				}
			}
		}
	}
	return ""
}

// readSitePackagesVersions walks site-packages looking for
// *.dist-info/METADATA files and extracts the Name + Version
// fields. Returns a lowercased-name → version map.
func readSitePackagesVersions(sitePackages string) map[string]string {
	out := map[string]string{}
	entries, err := os.ReadDir(sitePackages)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasSuffix(e.Name(), ".dist-info") {
			continue
		}
		meta := filepath.Join(sitePackages, e.Name(), "METADATA")
		f, err := os.Open(meta)
		if err != nil {
			continue
		}
		var name, version string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if name == "" && strings.HasPrefix(line, "Name: ") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			}
			if version == "" && strings.HasPrefix(line, "Version: ") {
				version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
			}
			if name != "" && version != "" {
				break
			}
		}
		f.Close()
		if name != "" && version != "" {
			out[strings.ToLower(name)] = version
		}
	}
	return out
}
