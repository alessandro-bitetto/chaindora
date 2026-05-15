package inventory

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

// parseMavenPOM extracts dependencies declared in a Maven pom.xml.
// Maven's resolution model means pom.xml describes WANTED
// dependencies, not always the resolved ones — the build tool
// (mvn / gradle) materializes the full graph at build time. For
// chaindora's purposes the declared deps are good enough as a
// detection inventory; gate-time resolution (v0.11.x) will use
// `mvn dependency:tree` to get the full tree.
//
// We emit a Package per (groupId, artifactId, version). PURL
// type is "maven" with namespace=groupId per the PURL spec.
//
// Property substitution: pom.xml's <version>${some.version}</version>
// requires resolving the property from <properties>. We handle
// the common case (direct property reference) but don't follow
// transitive substitution or parent-pom inheritance — that
// requires running Maven. Unresolved properties are skipped.
type mavenPOM struct {
	XMLName      xml.Name           `xml:"project"`
	GroupID      string             `xml:"groupId"`
	ArtifactID   string             `xml:"artifactId"`
	Version      string             `xml:"version"`
	Properties   mavenPropertiesXML `xml:"properties"`
	Dependencies struct {
		Dependency []mavenDep `xml:"dependency"`
	} `xml:"dependencies"`
	DependencyManagement struct {
		Dependencies struct {
			Dependency []mavenDep `xml:"dependency"`
		} `xml:"dependencies"`
	} `xml:"dependencyManagement"`
}

type mavenDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// mavenPropertiesXML is a passthrough XML element whose child
// names are arbitrary property keys. We decode it into a name→
// value map below.
type mavenPropertiesXML struct {
	Inner []mavenPropEntry `xml:",any"`
}

type mavenPropEntry struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

func parseMavenPOM(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pom mavenPOM
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, fmt.Errorf("parse pom.xml: %w", err)
	}
	props := map[string]string{}
	for _, p := range pom.Properties.Inner {
		props[p.XMLName.Local] = p.Value
	}
	// Add project-level coordinates as substitutable properties
	// — common pattern for sibling-module versions.
	if pom.Version != "" {
		props["project.version"] = pom.Version
	}
	if pom.GroupID != "" {
		props["project.groupId"] = pom.GroupID
	}

	deps := append([]mavenDep{}, pom.Dependencies.Dependency...)
	deps = append(deps, pom.DependencyManagement.Dependencies.Dependency...)

	seen := map[string]struct{}{}
	var packages []Package
	for _, d := range deps {
		groupID := resolveMavenProp(d.GroupID, props)
		artifactID := resolveMavenProp(d.ArtifactID, props)
		version := resolveMavenProp(d.Version, props)
		if groupID == "" || artifactID == "" || version == "" {
			continue
		}
		// Skip unresolved ${...} placeholders.
		if strings.HasPrefix(version, "${") {
			continue
		}
		// Skip test-scoped deps — chaindora's inventory is about
		// what lands in the runtime; test deps are out of scope
		// for the gate (mocks, junit, etc. are legit even when
		// they have CVEs).
		if d.Scope == "test" {
			continue
		}
		// Maven coordinate convention: groupId:artifactId, used
		// as the package name. PURL spec separates them
		// (namespace=groupId, name=artifactId) but chaindora's
		// internal Name field stores the combined form for
		// display consistency with other ecosystems.
		fullName := groupID + ":" + artifactID
		key := fullName + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		packages = append(packages, Package{
			Ecosystem:  EcosystemMavenCentral,
			Name:       fullName,
			Version:    version,
			PURL:       PURL(EcosystemMavenCentral, fullName, version),
			SourcePath: path,
		})
	}
	return packages, nil
}

// resolveMavenProp expands ${prop.key} references against the
// properties map. Single-level resolution only — transitive
// properties (a property whose value is itself ${...}) are left
// unresolved and the caller will skip them.
func resolveMavenProp(s string, props map[string]string) string {
	if !strings.Contains(s, "${") {
		return strings.TrimSpace(s)
	}
	for k, v := range props {
		s = strings.ReplaceAll(s, "${"+k+"}", v)
	}
	return strings.TrimSpace(s)
}
