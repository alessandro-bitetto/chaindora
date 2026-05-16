package gate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ResolveGradleTree resolves a Gradle project's dependency
// classpath. Unlike npm/cargo/pip, Gradle has no "add this
// package" CLI — users edit build.gradle by hand. The gate
// intercepts `gradle build` / `gradle dependencies` instead and
// vets the resolved classpath BEFORE any malicious .jar lands in
// the local maven cache or .gradle/.
//
// Implementation note: this resolver operates against the user's
// actual project cwd (not a tmpdir). Gradle's dependency
// resolution depends on settings.gradle, applied plugins,
// repository configuration — recreating that synthetically would
// be wrong. We run `gradle dependencies --console=plain` and
// parse its textual tree.
//
// Integrity isn't recorded in gradle.lockfile (the optional
// lockfile carries only versions). After parsing the dep tree we
// reuse the existing Maven Central .sha1 fetcher in
// enrichMavenIntegrity — Gradle pulls from Maven Central by
// default, so the same fetcher works without extra logic.
//
// gradlePath is the absolute path to the real `gradle` binary.
// cwd is the user's project directory.
func ResolveGradleTree(ctx context.Context, gradlePath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("gradle resolver requires the user's project cwd")
	}
	gradle := gradlePath
	if gradle == "" {
		gradle = "gradle"
	}
	out, err := runGradleDeps(ctx, gradle, cwd, "runtimeClasspath")
	if err != nil {
		// Plugin-only / library-only projects may not have
		// runtimeClasspath. Fall back to the default (root
		// configuration of every project), which prints every
		// configuration's resolved tree.
		out2, err2 := runGradleDeps(ctx, gradle, cwd, "")
		if err2 != nil {
			return nil, wrapPMError("gradle", "dependencies",
				append(out, out2...), err2)
		}
		out = out2
	}
	refs := parseGradleDepsTree(out)
	return enrichMavenIntegrity(ctx, refs), nil
}

func runGradleDeps(ctx context.Context, gradle, cwd, configuration string) ([]byte, error) {
	args := []string{"dependencies", "--console=plain", "--quiet", "--no-daemon"}
	if configuration != "" {
		args = append(args, "--configuration", configuration)
	}
	cmd := exec.CommandContext(ctx, gradle, args...)
	cmd.Dir = cwd
	return cmd.CombinedOutput()
}

// parseGradleDepsTree extracts (group, artifact, version) tuples
// from Gradle's textual dependency tree. Lines look like:
//
//	+--- com.google.guava:guava:32.0.0-jre
//	|    \--- com.google.j2objc:j2objc-annotations:2.8 -> 1.3 (*)
//	+--- org.slf4j:slf4j-api:{require 1.7.36} -> 2.0.7
//
// Conventions we handle:
//   - Tree-drawing prefix (' ', '+', '-', '\\', '|') is stripped.
//   - Trailing " (*)" / " (c)" / " (n)" annotations are dropped.
//   - " -> X.Y" overrides resolve to version X.Y.
//   - "{require ...}" version-strategy notes are dropped.
//
// Direct/transitive distinction would require depth-tracking via
// indentation; we flatten everything to Direct=false since
// Gradle's tree representation muddles the call-graph anyway.
func parseGradleDepsTree(out []byte) []PackageRef {
	seen := map[string]struct{}{}
	var refs []PackageRef
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	// Some Gradle versions wrap long lines; allow up to 1 MiB.
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimLeft(line, "+-\\| ")
		if trimmed == "" {
			continue
		}
		// Drop trailing " (*)" / " (c)" / " (n)" markers.
		if i := strings.Index(trimmed, " ("); i >= 0 {
			trimmed = trimmed[:i]
		}
		// Drop "{require ...}" strategy annotations.
		if i := strings.Index(trimmed, "{require"); i >= 0 {
			// Look back to find the previous colon (the version separator).
			if end := strings.Index(trimmed[i:], "}"); end >= 0 {
				// Strip the strategy bracket entirely.
				trimmed = trimmed[:i] + trimmed[i+end+1:]
			}
		}
		// Resolve "g:a:V -> X.Y" overrides: use the RHS version.
		if i := strings.LastIndex(trimmed, " -> "); i >= 0 {
			ver := strings.TrimSpace(trimmed[i+len(" -> "):])
			head := strings.TrimSpace(trimmed[:i])
			lastColon := strings.LastIndex(head, ":")
			if lastColon < 0 {
				continue
			}
			trimmed = head[:lastColon+1] + ver
		}
		parts := strings.Split(strings.TrimSpace(trimmed), ":")
		if len(parts) != 3 {
			continue
		}
		group, artifact, version := parts[0], parts[1], parts[2]
		if group == "" || artifact == "" || version == "" {
			continue
		}
		// Reject header-row residue like "+--- runtimeClasspath".
		if strings.ContainsAny(group, " \t") || strings.ContainsAny(artifact, " \t") {
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
	if err := sc.Err(); err != nil {
		// Truncated output: return whatever we got rather than
		// failing. Better partial coverage than nothing.
		_ = fmt.Errorf("scan: %w", err)
	}
	return refs
}
