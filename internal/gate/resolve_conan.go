package gate

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
)

// ResolveConanTree resolves what `conan install <recipe>` would
// build/install. Approach:
//   1. `conan graph info --requires=<recipe> --format=json`
//      (Conan 2.x) returns the full dependency graph as JSON
//      without building or downloading.
//   2. Parse each node, emitting a PackageRef per (name, version).
//
// Conan is unusual in that "integrity" maps to package_id (a
// deterministic hash over recipe + settings + options + deps).
// It's not a bytes-hash of an artifact, but it's stable per
// resolved build config — good enough for republish-guard
// (a tampered recipe would change the package_id).
//
// Conan packages can run arbitrary Python in recipe.py during
// graph evaluation. `graph info` evaluates recipes, so this isn't
// fully sandboxed; the gate's value is partial — it warns about
// known-bad recipes but can't prevent execution of a poisoned
// recipe during resolution itself. Treat conan coverage as
// best-effort.
//
// OSV doesn't catalog Conan recipes. Signal comes from
// integrity-republish and chdora's static-pattern checker.
//
// conanPath is the absolute path to the real `conan` binary.
func ResolveConanTree(ctx context.Context, conanPath string, installArgs []string) ([]PackageRef, error) {
	if len(installArgs) == 0 {
		return nil, errors.New("no conan install args supplied")
	}
	conan := conanPath
	if conan == "" {
		conan = "conan"
	}
	if installArgs[0] == "install" || installArgs[0] == "graph" {
		installArgs = installArgs[1:]
	}
	requires := []string{}
	for _, a := range installArgs {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		requires = append(requires, a)
	}
	if len(requires) == 0 {
		return nil, errors.New("no resolvable conan recipes in args")
	}

	args := []string{"graph", "info", "--format=json"}
	for _, r := range requires {
		args = append(args, "--requires", r)
	}
	cmd := exec.CommandContext(ctx, conan, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapPMError("conan", "graph info", out, err)
	}
	directs := map[string]struct{}{}
	for _, r := range requires {
		directs[conanRecipeName(r)] = struct{}{}
	}
	return parseConanGraph(out, directs), nil
}

// conanRecipeName strips a version constraint from a Conan
// recipe ref. "zlib/1.3.1" → "zlib". "boost/[>=1.80]" → "boost".
func conanRecipeName(s string) string {
	if i := strings.Index(s, "/"); i > 0 {
		return s[:i]
	}
	return s
}

// parseConanGraph parses `conan graph info --format=json`.
// Conan 2.x emits:
//
//	{
//	  "graph": {
//	    "nodes": {
//	      "0": { "ref": "conanfile" },
//	      "1": { "ref": "zlib/1.3.1#abcdef...", "package_id": "..." },
//	      ...
//	    }
//	  }
//	}
//
// Each non-root node's `ref` is `name/version#recipe_revision`
// — we use the recipe_revision (or package_id if present) as
// the integrity signal.
func parseConanGraph(data []byte, directs map[string]struct{}) []PackageRef {
	var resp struct {
		Graph struct {
			Nodes map[string]struct {
				Ref       string `json:"ref"`
				PackageID string `json:"package_id"`
			} `json:"nodes"`
		} `json:"graph"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, node := range resp.Graph.Nodes {
		if node.Ref == "" || node.Ref == "conanfile" {
			continue
		}
		// Ref shape: "name/version#recipe_revision" or just
		// "name/version" or "name/version@user/channel#revision".
		name, version, revision := parseConanRef(node.Ref)
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if node.PackageID != "" {
			integrity = "conan-id:" + node.PackageID
		} else if revision != "" {
			integrity = "conan-rev:" + revision
		}
		_, isDirect := directs[name]
		refs = append(refs, PackageRef{
			Ecosystem: "conan",
			Name:      name,
			Version:   version,
			Direct:    isDirect,
			Integrity: integrity,
		})
	}
	return refs
}

func parseConanRef(ref string) (name, version, revision string) {
	// Split off revision after '#'.
	if i := strings.Index(ref, "#"); i >= 0 {
		revision = ref[i+1:]
		ref = ref[:i]
	}
	// Strip @user/channel suffix.
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.Index(ref, "/"); i > 0 {
		name = ref[:i]
		version = ref[i+1:]
	} else {
		name = ref
	}
	return name, version, revision
}
