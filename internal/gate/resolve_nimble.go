package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ResolveNimbleTree parses nimble.lock — Nim's optional lockfile
// (nimble lock command). JSON format with sha1 per dep.
//
// nimblePath unused (parser is cwd-only).
func ResolveNimbleTree(ctx context.Context, nimblePath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("nimble resolver requires the user's project cwd")
	}
	data, err := os.ReadFile(filepath.Join(cwd, "nimble.lock"))
	if err != nil {
		return nil, fmt.Errorf("read nimble.lock: %w", err)
	}
	return parseNimbleLock(data)
}

// parseNimbleLock — nimble.lock schema:
//
//	{
//	  "version": 1,
//	  "packages": {
//	    "regex": {
//	      "version": "0.21.0",
//	      "vcsRevision": "abcdef...",
//	      "url": "https://github.com/.../regex.git",
//	      "downloadMethod": "git",
//	      "dependencies": ["unicodedb"],
//	      "checksums": {"sha1": "..."}
//	    }
//	  }
//	}
func parseNimbleLock(data []byte) ([]PackageRef, error) {
	var lock struct {
		Packages map[string]struct {
			Version     string `json:"version"`
			VcsRevision string `json:"vcsRevision"`
			Checksums   struct {
				Sha1 string `json:"sha1"`
			} `json:"checksums"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse nimble.lock: %w", err)
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	for name, entry := range lock.Packages {
		if entry.Version == "" {
			continue
		}
		key := name + "@" + entry.Version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if entry.Checksums.Sha1 != "" {
			integrity = "sha1:" + entry.Checksums.Sha1
		} else if entry.VcsRevision != "" {
			integrity = "git:" + entry.VcsRevision
		}
		refs = append(refs, PackageRef{
			Ecosystem: "nimble",
			Name:      name,
			Version:   entry.Version,
			Integrity: integrity,
		})
	}
	return refs, nil
}
