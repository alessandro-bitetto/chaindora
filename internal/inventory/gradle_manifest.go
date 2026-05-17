package inventory

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// parseGradleManifest parses a build.gradle (Groovy DSL) or
// build.gradle.kts (Kotlin DSL) manifest. Like .csproj, this is a
// MANIFEST not a lockfile — versions are constraints, often
// resolved from external version-catalog files or compose-bom
// imports. chdora's lockfile parser (parseGradleLockfile) only
// fires when `gradle.lockfile` exists (opt-in via Gradle's
// `dependencyLocking` block). This fallback covers the common
// case where projects skip lockfile opt-in.
//
// Approach: regex-extract `implementation "group:name:version"`
// and the Kotlin-DSL parenthesized form
// `implementation("group:name:version")`. Also catches
// `api`, `compileOnly`, `runtimeOnly`, `testImplementation`,
// and the `version()` builder when used inline.
//
// What we miss without true resolution:
//   - Transitive deps (we only see what's directly declared).
//   - Version catalogs (`libs.versions.toml` referenced as
//     `libs.foo` — we'd need to load the catalog separately).
//   - BOM-imported versions (compose-bom etc. — version
//     comes from the BOM at resolve time).
//   - Property-substituted versions (`$junit_version`).
//
// All three are real-world common; the fallback's best-effort
// inventory is better than nothing but worse than a real
// lockfile. Recommend enabling `dependencyLocking` for full
// coverage.
func parseGradleManifest(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	// Allow long lines (Gradle build files can have long DSL chains).
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		for _, m := range gradleDepRE.FindAllStringSubmatch(sc.Text(), -1) {
			coord := m[1]
			parts := strings.Split(coord, ":")
			if len(parts) < 2 {
				continue
			}
			group, artifact := parts[0], parts[1]
			version := ""
			if len(parts) >= 3 {
				version = parts[2]
			}
			// Skip property-interpolation placeholders.
			if strings.Contains(version, "$") {
				version = ""
			}
			if group == "" || artifact == "" {
				continue
			}
			fullName := group + ":" + artifact
			key := fullName + "@" + version
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, Package{
				Ecosystem:  EcosystemMavenCentral,
				Name:       fullName,
				Version:    version,
				PURL:       PURL(EcosystemMavenCentral, fullName, version),
				SourcePath: path,
			})
		}
	}
	return out, nil
}

// gradleDepRE matches both Groovy and Kotlin DSL forms of inline
// `group:name:version` coordinate strings:
//
//	implementation 'org.foo:bar:1.2.3'
//	implementation "org.foo:bar:1.2.3"
//	implementation("org.foo:bar:1.2.3")
//	api group: 'org.foo', name: 'bar', version: '1.2.3'   ← NOT matched (different shape)
//
// The kw-only form (group:..., name:..., version:...) is rare in
// modern Gradle; skip for v0.15.2 simplicity.
var gradleDepRE = regexp.MustCompile(`['"]([\w\.\-]+:[\w\.\-]+(?::[\w\.\-]+)?)['"]`)

// hasGradleLockfileSibling reports whether `gradle.lockfile`
// exists in the same dir as a build.gradle / build.gradle.kts.
// If present, the lockfile parser wins — skip the manifest fallback.
func hasGradleLockfileSibling(buildGradlePath string) bool {
	sibling := filepath.Join(filepath.Dir(buildGradlePath), "gradle.lockfile")
	_, err := os.Stat(sibling)
	return err == nil
}
