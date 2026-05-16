package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveShardsTree parses shard.lock — Crystal's lockfile.
// Format (YAML-like, but with a custom shard-spec syntax):
//
//	version: 2.0
//	shards:
//	  ameba:
//	    git: https://github.com/crystal-ameba/ameba.git
//	    version: 1.6.0
//	    commit: abc123...
//
// Some entries use `path:` for local deps — skipped.
//
// shardsPath unused (parser is cwd-only).
func ResolveShardsTree(ctx context.Context, shardsPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("shards resolver requires the user's project cwd")
	}
	data, err := os.ReadFile(filepath.Join(cwd, "shard.lock"))
	if err != nil {
		return nil, fmt.Errorf("read shard.lock: %w", err)
	}
	return parseShardLock(data), nil
}

func parseShardLock(data []byte) []PackageRef {
	seen := map[string]struct{}{}
	var refs []PackageRef
	var currentName, currentVersion, currentCommit string
	inShards := false
	flush := func() {
		defer func() {
			currentName, currentVersion, currentCommit = "", "", ""
		}()
		if currentName == "" || currentVersion == "" {
			return
		}
		key := currentName + "@" + currentVersion
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		integrity := ""
		if currentCommit != "" {
			integrity = "git:" + currentCommit
		}
		refs = append(refs, PackageRef{
			Ecosystem: "shards",
			Name:      currentName,
			Version:   currentVersion,
			Integrity: integrity,
		})
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if line == "shards:" {
			inShards = true
			continue
		}
		if !inShards {
			continue
		}
		// Top-level shard name: 2-space indent, ends with ':'.
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(trimmed, ":") {
			flush()
			currentName = strings.TrimSuffix(trimmed, ":")
			continue
		}
		// Sub-fields: 4-space indent.
		if strings.HasPrefix(line, "    ") {
			eq := strings.Index(trimmed, ":")
			if eq < 0 {
				continue
			}
			key := strings.TrimSpace(trimmed[:eq])
			val := strings.TrimSpace(trimmed[eq+1:])
			switch key {
			case "version":
				currentVersion = val
			case "commit":
				currentCommit = val
			}
		}
	}
	flush()
	return refs
}
