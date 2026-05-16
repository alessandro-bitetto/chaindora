package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ResolveElmTree parses elm.json (Elm 0.19+). Elm packages don't
// carry per-package content hashes in elm.json — the Elm
// architecture relies on package signing at publish time. We emit
// (author/repo, version) tuples for the OSV checker and skip
// integrity. (Elm has no OSV ecosystem either, so impact is
// limited to cooldown / publisher signals via custom probes.)
//
// elmPath unused (parser is cwd-only).
func ResolveElmTree(ctx context.Context, elmPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("elm resolver requires the user's project cwd")
	}
	data, err := os.ReadFile(filepath.Join(cwd, "elm.json"))
	if err != nil {
		return nil, fmt.Errorf("read elm.json: %w", err)
	}
	return parseElmJSON(data)
}

func parseElmJSON(data []byte) ([]PackageRef, error) {
	// Elm has two schema variants (application vs package). Both
	// expose `dependencies.direct` and `dependencies.indirect`
	// maps of "<author>/<pkg>" → version.
	var manifest struct {
		Dependencies struct {
			Direct   map[string]string `json:"direct"`
			Indirect map[string]string `json:"indirect"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse elm.json: %w", err)
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	emit := func(deps map[string]string, direct bool) {
		for name, version := range deps {
			key := name + "@" + version
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			refs = append(refs, PackageRef{
				Ecosystem: "elm",
				Name:      name,
				Version:   version,
				Direct:    direct,
			})
		}
	}
	emit(manifest.Dependencies.Direct, true)
	emit(manifest.Dependencies.Indirect, false)
	return refs, nil
}
