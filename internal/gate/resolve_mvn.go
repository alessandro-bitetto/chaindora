package gate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ResolveMavenTree resolves what a Maven dependency would pull
// in transitively. Approach:
//   1. tmpdir with a minimal pom.xml declaring the requested
//      dependencies.
//   2. `mvn dependency:list -DincludeScope=runtime` writes the
//      flat resolved list to stdout.
//   3. Parse "groupId:artifactId:type:version:scope" lines.
//
// Run inside a tmpdir with a fresh local-repo (-Dmaven.repo.local)
// so the resolution doesn't pollute the user's ~/.m2.
//
// mvnPath is the absolute path to the real mvn binary. Tests
// can pass "".
func ResolveMavenTree(ctx context.Context, mvnPath string, addArgs []string) ([]PackageRef, error) {
	if len(addArgs) == 0 {
		return nil, errors.New("no maven coordinates supplied")
	}
	mvn := mvnPath
	if mvn == "" {
		mvn = "mvn"
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-mvn-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)
	localRepo := filepath.Join(tmp, ".m2")
	if err := os.MkdirAll(localRepo, 0o755); err != nil {
		return nil, err
	}

	coords, err := parseMavenAddArgs(addArgs)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>chdora.gate</groupId>
  <artifactId>resolve</artifactId>
  <version>0.0.0</version>
  <packaging>pom</packaging>
  <dependencies>
`)
	for _, c := range coords {
		fmt.Fprintf(&b, "    <dependency>\n      <groupId>%s</groupId>\n      <artifactId>%s</artifactId>\n      <version>%s</version>\n    </dependency>\n", c.group, c.artifact, c.version)
	}
	b.WriteString(`  </dependencies>
</project>
`)
	if err := os.WriteFile(filepath.Join(tmp, "pom.xml"), []byte(b.String()), 0o644); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, mvn,
		"-q", "-B",
		"-Dmaven.repo.local="+localRepo,
		"dependency:list",
		"-DincludeScope=runtime",
		"-DoutputFile=deps.txt",
		"-DappendOutput=false",
	)
	cmd.Dir = tmp
	if out, err := cmd.CombinedOutput(); err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 400 {
			snippet = snippet[:400] + "..."
		}
		return nil, fmt.Errorf("mvn dependency:list failed: %w\n%s", err, snippet)
	}
	data, err := os.ReadFile(filepath.Join(tmp, "deps.txt"))
	if err != nil {
		return nil, fmt.Errorf("read mvn deps.txt: %w", err)
	}
	return parseMavenDepsList(data, coords), nil
}

type mavenCoord struct {
	group    string
	artifact string
	version  string
}

// parseMavenAddArgs accepts `groupId:artifactId:version` shorthand.
func parseMavenAddArgs(args []string) ([]mavenCoord, error) {
	var out []mavenCoord
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		parts := strings.Split(a, ":")
		if len(parts) < 3 {
			return nil, fmt.Errorf("maven coordinate %q must be groupId:artifactId:version", a)
		}
		out = append(out, mavenCoord{
			group:    parts[0],
			artifact: parts[1],
			version:  parts[2],
		})
	}
	if len(out) == 0 {
		return nil, errors.New("no resolvable maven coordinates")
	}
	return out, nil
}

// parseMavenDepsList parses `mvn dependency:list -DoutputFile`
// output. Each line is roughly:
//   "   com.google.guava:guava:jar:32.0.0-jre:compile"
// We accept any number of leading spaces and trim a "(optional)"
// suffix some maven plugins add.
func parseMavenDepsList(data []byte, directs []mavenCoord) []PackageRef {
	directNames := map[string]struct{}{}
	for _, d := range directs {
		directNames[d.group+":"+d.artifact] = struct{}{}
	}
	var refs []PackageRef
	seen := map[string]struct{}{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "The following") || strings.HasPrefix(line, "none") {
			continue
		}
		// Trim "(optional)" / "-- module ..." trailer.
		if i := strings.Index(line, " --"); i > 0 {
			line = line[:i]
		}
		if i := strings.Index(line, " ("); i > 0 {
			line = line[:i]
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		group := parts[0]
		artifact := parts[1]
		// parts[2] is the type (jar, war, pom, ...) — skip.
		version := parts[3]
		if group == "" || artifact == "" || version == "" {
			continue
		}
		fullName := group + ":" + artifact
		key := fullName + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		_, isDirect := directNames[fullName]
		refs = append(refs, PackageRef{
			Ecosystem: "maven",
			Name:      fullName,
			Version:   version,
			Direct:    isDirect,
		})
	}
	return refs
}
