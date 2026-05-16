package gate

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

// ResolveSBTTree resolves the resolved classpath of an sbt-based
// Scala project. sbt has no install-args verb — users edit
// build.sbt by hand. The gate runs `sbt 'show externalDependencyClasspath'`
// or equivalent against the user's cwd.
//
// Implementation: invoke `coursier resolve` (sbt uses Coursier
// for resolution since sbt 1.x) if available — it has a clean
// JSON output. If coursier isn't present, fall back to parsing
// `sbt dependencyTree` output.
//
// sbtPath is the absolute path to the real `sbt` binary.
func ResolveSBTTree(ctx context.Context, sbtPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("sbt resolver requires the user's project cwd")
	}
	sbt := sbtPath
	if sbt == "" {
		sbt = "sbt"
	}
	// sbt dependencyTree (from sbt-dependency-graph plugin, bundled
	// in sbt 1.4+) prints a textual tree to stdout.
	cmd := exec.CommandContext(ctx, sbt, "--error", "--batch", "dependencyTree")
	cmd.Dir = cwd
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapPMError("sbt", "dependencyTree", out, err)
	}
	refs := parseSBTDependencyTree(out)
	return enrichMavenIntegrity(ctx, refs), nil
}

// parseSBTDependencyTree extracts (org, name, version) tuples
// from `sbt dependencyTree` output. Lines look like:
//
//	[info] org.scalatest:scalatest_2.13:3.2.16
//	[info]   +-org.scalactic:scalactic_2.13:3.2.16
//
// Same Maven coordinate shape as our existing maven resolver.
func parseSBTDependencyTree(out []byte) []PackageRef {
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		// Strip "[info]" prefix and tree-drawing chars.
		trimmed = strings.TrimPrefix(trimmed, "[info]")
		trimmed = strings.TrimLeft(trimmed, " \t+-|\\")
		trimmed = strings.TrimSpace(trimmed)
		// Drop "(evicted by: X.Y)" annotations.
		if i := strings.Index(trimmed, " ("); i >= 0 {
			trimmed = trimmed[:i]
		}
		parts := strings.Split(trimmed, ":")
		if len(parts) != 3 {
			continue
		}
		group, artifact, version := parts[0], parts[1], parts[2]
		if group == "" || artifact == "" || version == "" {
			continue
		}
		if strings.ContainsAny(group, " \t[") {
			continue
		}
		fullName := group + ":" + artifact
		key := fullName + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, PackageRef{
			Ecosystem: "maven",
			Name:      fullName,
			Version:   version,
		})
	}
	return refs
}
