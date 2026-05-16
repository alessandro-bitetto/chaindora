package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ResolveRenvTree parses renv.lock — the R/renv ecosystem's
// per-project dependency snapshot. JSON format with one entry
// per package, including version and Hash (md5 for CRAN; sha
// for Bioconductor; commit for git).
//
// rPath unused (parser is cwd-only).
func ResolveRenvTree(ctx context.Context, rPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("renv resolver requires the user's project cwd")
	}
	data, err := os.ReadFile(filepath.Join(cwd, "renv.lock"))
	if err != nil {
		return nil, fmt.Errorf("read renv.lock: %w", err)
	}
	return parseRenvLock(data)
}

// parseRenvLock parses renv.lock JSON. Schema:
//
//	{
//	  "R": { "Version": "4.3.0", "Repositories": [...] },
//	  "Packages": {
//	    "dplyr": {
//	      "Package": "dplyr",
//	      "Version": "1.1.4",
//	      "Source": "Repository",
//	      "Repository": "CRAN",
//	      "Hash": "fedd9d00c2944ff00a0e2696ccf048ec"
//	    },
//	    ...
//	  }
//	}
func parseRenvLock(data []byte) ([]PackageRef, error) {
	var lock struct {
		Packages map[string]struct {
			Package  string `json:"Package"`
			Version  string `json:"Version"`
			Source   string `json:"Source"`
			Hash     string `json:"Hash"`
			RemoteRef string `json:"RemoteRef"`
		} `json:"Packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse renv.lock: %w", err)
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, entry := range lock.Packages {
		name := entry.Package
		version := entry.Version
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if entry.Hash != "" {
			integrity = "renv-hash:" + entry.Hash
		}
		refs = append(refs, PackageRef{
			Ecosystem: "cran",
			Name:      name,
			Version:   version,
			Integrity: integrity,
		})
	}
	return refs, nil
}
