package gate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ResolveStackTree resolves the Haskell dependency set declared
// by the user's stack.yaml. Stack has no "add this dep" CLI;
// users edit stack.yaml / package.yaml and run `stack build` or
// `stack ls dependencies`. Gate runs against the user's cwd.
//
// stackPath is the absolute path to the real `stack` binary.
func ResolveStackTree(ctx context.Context, stackPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("stack resolver requires the user's project cwd")
	}
	stack := stackPath
	if stack == "" {
		stack = "stack"
	}
	// Prefer parsing stack.yaml.lock when present — it has
	// sha256 (pantry-tree hashes) per package without needing to
	// resolve anything live.
	if b, err := os.ReadFile(filepath.Join(cwd, "stack.yaml.lock")); err == nil {
		if refs := parseStackYamlLock(b); len(refs) > 0 {
			return refs, nil
		}
	}
	// Fallback: shell out to `stack ls dependencies --json` which
	// emits one JSON object per dep.
	cmd := exec.CommandContext(ctx, stack, "ls", "dependencies", "json", "--no-include-base")
	cmd.Dir = cwd
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapPMError("stack", "ls dependencies", out, err)
	}
	return parseStackLsJSON(out), nil
}

// parseStackYamlLock parses stack.yaml.lock — YAML with `packages`
// array of {original, completed} pairs where completed carries
// `pantry-tree` and `cabal-file` sha256 hashes.
func parseStackYamlLock(data []byte) []PackageRef {
	var lock struct {
		Packages []struct {
			Completed struct {
				Hackage    string `yaml:"hackage"`
				PantryTree struct {
					Sha    string `yaml:"sha256"`
					Size   int    `yaml:"size"`
					Subdir string `yaml:"subdir"`
				} `yaml:"pantry-tree"`
			} `yaml:"completed"`
		} `yaml:"packages"`
		Snapshots []struct {
			Completed struct {
				URL string `yaml:"url"`
				Sha string `yaml:"sha256"`
			} `yaml:"completed"`
		} `yaml:"snapshots"`
	}
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, p := range lock.Packages {
		// Hackage entries look like "aeson-2.1.2.1@sha256:abc..."
		// — split on '-' from the end.
		spec := p.Completed.Hackage
		if spec == "" {
			continue
		}
		// Split off "@sha256:..." suffix.
		if i := strings.Index(spec, "@"); i >= 0 {
			spec = spec[:i]
		}
		// Last '-' separates name from version.
		dash := strings.LastIndex(spec, "-")
		if dash <= 0 {
			continue
		}
		name := spec[:dash]
		version := spec[dash+1:]
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if p.Completed.PantryTree.Sha != "" {
			integrity = "sha256:" + p.Completed.PantryTree.Sha
		}
		refs = append(refs, PackageRef{
			Ecosystem: "hackage",
			Name:      name,
			Version:   version,
			Integrity: integrity,
		})
	}
	return refs
}

// parseStackLsJSON parses `stack ls dependencies json` output,
// which is a stream of JSON objects (one per dep, newline-separated
// — not a JSON array).
func parseStackLsJSON(out []byte) []PackageRef {
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var entry struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry.Name == "" || entry.Version == "" {
			continue
		}
		key := entry.Name + "@" + entry.Version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, PackageRef{
			Ecosystem: "hackage",
			Name:      entry.Name,
			Version:   entry.Version,
		})
	}
	return refs
}
