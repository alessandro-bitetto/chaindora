package inventory

import (
	"os"
	"strings"
)

// parseShardLock parses Crystal's shard.lock. Format is YAML-ish:
//
//	version: 2.0
//	shards:
//	  ameba:
//	    git: https://github.com/crystal-ameba/ameba.git
//	    version: 1.6.0
//	    commit: abc123...
func parseShardLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	var currentName, currentVersion, currentCommit string
	inShards := false
	flush := func() {
		defer func() { currentName, currentVersion, currentCommit = "", "", "" }()
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
		out = append(out, Package{
			Ecosystem:  EcosystemShards,
			Name:       currentName,
			Version:    currentVersion,
			PURL:       PURL(EcosystemShards, currentName, currentVersion),
			SourcePath: path,
			Integrity:  integrity,
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
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(trimmed, ":") {
			flush()
			currentName = strings.TrimSuffix(trimmed, ":")
			continue
		}
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
	return out, nil
}
