package inventory

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

// parseCsprojManifest parses a .NET project file (.csproj / .fsproj /
// .vbproj). These are MSBuild XML manifests, NOT lockfiles —
// `<PackageReference Include="..." Version="..."/>` carries a version
// constraint (often a range like "1.2.*"), not the resolved pin that
// `packages.lock.json` would record.
//
// chdora's NuGet lockfile parser (parseNuGetPackagesLock) only fires
// when `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`
// is set in the project — and most .NET projects in the wild don't
// have that enabled. This fallback fills the gap: at least we know
// what packages a project DECLARES, even without resolved versions.
//
// Tradeoffs of the fallback:
//   - OSV-MAL matching by name still works for high-confidence
//     malicious-package hits (MAL-* is often name-only).
//   - OSV-CVE matching is limited because OSV's batch API requires
//     exact versions; ranges like "1.2.*" fail the lookup.
//   - Predictive cooldown / publisher-change / maintainer-trust
//     all need a concrete version and silently no-op for ranges.
//   - Incident-pack name-only entries match fine; version-specific
//     entries depend on whether the range happens to overlap.
//
// The inventory.Scan dispatcher only fires this fallback when no
// sibling `packages.lock.json` exists — when the user has the
// real lockfile, the lockfile parser wins (more precise).
func parseCsprojManifest(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Two forms appear in the wild:
	//   <PackageReference Include="X" Version="Y" />
	//   <PackageReference Include="X"><Version>Y</Version></PackageReference>
	type pkgRef struct {
		XMLName    xml.Name `xml:"PackageReference"`
		Include    string   `xml:"Include,attr"`
		Version    string   `xml:"Version,attr"`
		ChildVer   string   `xml:"Version"`
	}
	type itemGroup struct {
		PackageRefs []pkgRef `xml:"PackageReference"`
	}
	type project struct {
		XMLName    xml.Name    `xml:"Project"`
		ItemGroups []itemGroup `xml:"ItemGroup"`
	}
	var proj project
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	for _, g := range proj.ItemGroups {
		for _, p := range g.PackageRefs {
			name := strings.TrimSpace(p.Include)
			version := strings.TrimSpace(p.Version)
			if version == "" {
				version = strings.TrimSpace(p.ChildVer)
			}
			if name == "" {
				continue
			}
			// Skip MSBuild property-substitution placeholders we
			// can't resolve statically: `$(NewtonsoftJsonVersion)`.
			// We still record the package name (the user might
			// want to know it's a dep) but with empty version.
			if strings.HasPrefix(version, "$(") && strings.HasSuffix(version, ")") {
				version = ""
			}
			key := name + "@" + version
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, Package{
				Ecosystem:  EcosystemNuGet,
				Name:       name,
				Version:    version,
				PURL:       PURL(EcosystemNuGet, name, version),
				SourcePath: path,
			})
		}
	}
	return out, nil
}

// hasNuGetLockfileSibling reports whether a packages.lock.json
// exists alongside the given .csproj. Used by the dispatcher to
// skip the manifest fallback when the real lockfile is present.
func hasNuGetLockfileSibling(csprojPath string) bool {
	sibling := filepath.Join(filepath.Dir(csprojPath), "packages.lock.json")
	_, err := os.Stat(sibling)
	return err == nil
}
