package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ResolveSwiftPMTree resolves the dependency set for a Swift
// package. Swift PM has no "add this dep" CLI in older versions
// (5.5+ has `swift package add-dependency`); users typically edit
// Package.swift. The gate intercepts `swift package resolve` and
// `swift package update`.
//
// Implementation: run `swift package resolve` IN THE USER'S CWD
// (Swift PM needs the real Package.swift + sources for
// resolution). Parse the resulting Package.resolved JSON.
//
// Swift PM packages are git-anchored — `Package.resolved`
// records a commit revision per dependency rather than a content
// hash. We use the revision as Integrity. A republish-style
// attack here would require force-pushing over a commit, which
// would itself change the revision — so the integrity signal is
// equivalent in practice.
//
// swiftPath is the absolute path to the real `swift` binary; cwd
// is the user's project directory.
func ResolveSwiftPMTree(ctx context.Context, swiftPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("swift PM resolver requires the user's project cwd")
	}
	swift := swiftPath
	if swift == "" {
		swift = "swift"
	}
	cmd := exec.CommandContext(ctx, swift, "package", "resolve")
	cmd.Dir = cwd
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapPMError("swift", "package resolve", out, err)
	}
	data, err := os.ReadFile(filepath.Join(cwd, "Package.resolved"))
	if err != nil {
		return nil, fmt.Errorf("read Package.resolved: %w", err)
	}
	return parseSwiftPMResolved(data)
}

// parseSwiftPMResolved parses Package.resolved. Schema v2:
//
//	{
//	  "pins": [
//	    {
//	      "identity": "alamofire",
//	      "kind": "remoteSourceControl",
//	      "location": "https://github.com/Alamofire/Alamofire.git",
//	      "state": {
//	        "revision": "abc123...",
//	        "version": "5.8.0"
//	      }
//	    }
//	  ],
//	  "version": 2
//	}
//
// Schema v1 used `pins[].package` and `pins[].repositoryURL` —
// both fields covered.
func parseSwiftPMResolved(data []byte) ([]PackageRef, error) {
	var resolved struct {
		Pins []struct {
			Identity      string `json:"identity"`
			Package       string `json:"package"`
			Location      string `json:"location"`
			RepositoryURL string `json:"repositoryURL"`
			State         struct {
				Revision string `json:"revision"`
				Version  string `json:"version"`
				Branch   string `json:"branch"`
			} `json:"state"`
		} `json:"pins"`
	}
	if err := json.Unmarshal(data, &resolved); err != nil {
		return nil, fmt.Errorf("parse Package.resolved: %w", err)
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, p := range resolved.Pins {
		name := p.Identity
		if name == "" {
			name = p.Package
		}
		version := p.State.Version
		if version == "" {
			version = p.State.Branch
		}
		if name == "" || (version == "" && p.State.Revision == "") {
			continue
		}
		// Fall back to revision if no version is pinned.
		if version == "" {
			version = p.State.Revision
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if p.State.Revision != "" {
			integrity = "git:" + p.State.Revision
		}
		refs = append(refs, PackageRef{
			Ecosystem: "swift",
			Name:      name,
			Version:   version,
			Integrity: integrity,
		})
	}
	return refs, nil
}
