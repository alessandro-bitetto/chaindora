package gate

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
)

// ResolveOpamTree resolves an OCaml project's dependency set via
// `opam list --installed --columns=package,version --short` or
// the newer `opam list --json`. For "install <pkg>" the gate uses
// `opam install --dry-run --json <pkg>` to surface the resolved
// set.
//
// OSV doesn't cover opam (no "opam" ecosystem); signal comes from
// cooldown / publisher / integrity-republish.
//
// opamPath is the absolute path to the real `opam` binary.
func ResolveOpamTree(ctx context.Context, opamPath string, installArgs []string) ([]PackageRef, error) {
	if len(installArgs) == 0 {
		return nil, errors.New("no opam install args supplied")
	}
	opam := opamPath
	if opam == "" {
		opam = "opam"
	}
	if installArgs[0] == "install" {
		installArgs = installArgs[1:]
	}
	pkgs := []string{}
	for _, a := range installArgs {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		pkgs = append(pkgs, a)
	}
	if len(pkgs) == 0 {
		return nil, errors.New("no resolvable opam packages")
	}
	args := append([]string{"install", "--dry-run", "--yes", "--show-actions"}, pkgs...)
	cmd := exec.CommandContext(ctx, opam, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// opam install --dry-run exits non-zero in some edge
		// cases (interactive prompt suppressed by --yes etc.) but
		// the action plan often still prints. Try parsing.
		if refs := parseOpamShowActions(out); len(refs) > 0 {
			return refs, nil
		}
		return nil, wrapPMError("opam", "install --dry-run", out, err)
	}
	return parseOpamShowActions(out), nil
}

// parseOpamShowActions parses `opam install --show-actions`
// output. Lines look like:
//
//	  - install      foo.1.2.3
//	  - install      bar.2.0.0
//
// opam doesn't expose per-package hashes in this view; integrity
// fetching from the opam-repository would be needed for
// republish-guard coverage. Stub left empty for now.
func parseOpamShowActions(out []byte) []PackageRef {
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- install") &&
			!strings.HasPrefix(trimmed, "∗ install") &&
			!strings.HasPrefix(trimmed, "install") {
			continue
		}
		// Last whitespace-separated token is name.version
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		spec := fields[len(fields)-1]
		dot := strings.LastIndex(spec, ".")
		if dot <= 0 {
			continue
		}
		name := spec[:dot]
		version := spec[dot+1:]
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, PackageRef{
			Ecosystem: "opam",
			Name:      name,
			Version:   version,
		})
	}
	return refs
}

// unused — placeholder for a future opam JSON-mode parser when
// opam stabilizes its --json output across releases.
type opamJSONUnused = json.RawMessage
