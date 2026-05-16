package gate

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
)

// ResolveBrewTree resolves what `brew install <formula>` would
// install, including build/runtime dependencies. Approach:
//   1. `brew info --json=v2 <formula> [<formula> ...]` returns a
//      JSON object per requested formula with name, versions,
//      and dependency arrays + stable.url + bottle.files.
//   2. Walk the deps recursively, fetching each dep's info too.
//   3. Use bottle's sha256 (Homebrew always builds bottles for
//      core formulae) or stable source URL's sha256 as integrity.
//
// Homebrew is interesting: formulae are Ruby files in git-managed
// taps, and `brew install` runs arbitrary install logic from the
// formula. The supply-chain attack surface is REAL (2024
// fake-Homebrew Google Ads malware campaign infected lots of
// macOS devs). The gate's value here is significant.
//
// OSV doesn't cover Homebrew. Signal comes from the integrity
// republish-guard, plus chdora's own incident-pack matcher.
//
// brewPath is the absolute path to the real `brew` binary.
func ResolveBrewTree(ctx context.Context, brewPath string, installArgs []string) ([]PackageRef, error) {
	if len(installArgs) == 0 {
		return nil, errors.New("no brew install args supplied")
	}
	brew := brewPath
	if brew == "" {
		brew = "brew"
	}
	// Strip a leading "install" verb token.
	if installArgs[0] == "install" {
		installArgs = installArgs[1:]
	}
	directs := map[string]struct{}{}
	queue := []string{}
	for _, a := range installArgs {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		// Strip tap prefix: "homebrew/core/foo" → "foo" for
		// uniqueness, but keep the full name as the queue entry so
		// brew info finds it.
		directs[brewFormulaName(a)] = struct{}{}
		queue = append(queue, a)
	}
	if len(queue) == 0 {
		return nil, errors.New("no resolvable brew formulae in args")
	}

	visited := map[string]struct{}{}
	var refs []PackageRef
	for len(queue) > 0 {
		// Fetch up to 16 formulae per `brew info` call (brew
		// accepts multiple args and batches them).
		batch := queue
		if len(batch) > 16 {
			batch = batch[:16]
			queue = queue[16:]
		} else {
			queue = nil
		}
		args := append([]string{"info", "--json=v2"}, batch...)
		cmd := exec.CommandContext(ctx, brew, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, wrapPMError("brew", "info --json=v2", out, err)
		}
		newDeps, batchRefs := parseBrewInfo(out, directs, visited)
		refs = append(refs, batchRefs...)
		// Enqueue unseen dependencies for the next pass.
		for _, d := range newDeps {
			if _, seen := visited[d]; seen {
				continue
			}
			queue = append(queue, d)
		}
	}
	return refs, nil
}

// brewFormulaName strips a tap prefix from a formula spec.
//   "homebrew/core/foo" → "foo"
//   "user/tap/foo"      → "foo"
//   "foo"               → "foo"
func brewFormulaName(s string) string {
	parts := strings.Split(s, "/")
	return parts[len(parts)-1]
}

// parseBrewInfo extracts PackageRefs for the formulae in one
// `brew info --json=v2` response and returns the deduped list of
// new dependencies to visit next.
func parseBrewInfo(data []byte, directs map[string]struct{}, visited map[string]struct{}) (newDeps []string, refs []PackageRef) {
	var resp struct {
		Formulae []struct {
			Name     string `json:"name"`
			FullName string `json:"full_name"`
			Versions struct {
				Stable string `json:"stable"`
			} `json:"versions"`
			URLs struct {
				Stable struct {
					URL      string `json:"url"`
					Checksum string `json:"checksum"`
				} `json:"stable"`
			} `json:"urls"`
			Bottle struct {
				Stable struct {
					Files map[string]struct {
						URL    string `json:"url"`
						Sha256 string `json:"sha256"`
					} `json:"files"`
				} `json:"stable"`
			} `json:"bottle"`
			Dependencies      []string `json:"dependencies"`
			RecommendedDeps   []string `json:"recommended_dependencies"`
			OptionalDeps      []string `json:"optional_dependencies"`
			BuildDependencies []string `json:"build_dependencies"`
		} `json:"formulae"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, nil
	}
	for _, f := range resp.Formulae {
		if _, seen := visited[f.Name]; seen {
			continue
		}
		visited[f.Name] = struct{}{}
		version := f.Versions.Stable
		// Prefer bottle sha256 (the binary actually installed on
		// macOS). Pick any architecture's sha256 — they're all
		// content hashes of distinct bottles, and we just need
		// SOMETHING stable per (name, version) to key the cache.
		integrity := ""
		for _, bot := range f.Bottle.Stable.Files {
			if bot.Sha256 != "" {
				integrity = "sha256:" + bot.Sha256
				break
			}
		}
		// Fall back to stable-source sha256 if no bottle available.
		if integrity == "" && f.URLs.Stable.Checksum != "" {
			integrity = "sha256:" + f.URLs.Stable.Checksum
		}
		_, isDirect := directs[f.Name]
		refs = append(refs, PackageRef{
			Ecosystem: "homebrew",
			Name:      f.Name,
			Version:   version,
			Direct:    isDirect,
			Integrity: integrity,
		})
		// Enqueue all dep classes (dependencies + recommended +
		// build). Optional excluded — they're not auto-installed.
		newDeps = append(newDeps, f.Dependencies...)
		newDeps = append(newDeps, f.RecommendedDeps...)
		newDeps = append(newDeps, f.BuildDependencies...)
	}
	return newDeps, refs
}
