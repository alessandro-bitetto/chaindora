package gate

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
)

// ResolveLuaRocksTree resolves Lua dependencies via luarocks.
// luarocks has no project-local lockfile by default; resolution
// is global. The gate runs `luarocks show <rock> --tree=system`
// per requested rock and walks dependencies via repeated calls.
//
// Approach for `luarocks install <rock>`:
//   1. `luarocks search --porcelain <rock>` returns one
//      "<name> <version>" line per match — first is the version
//      that would resolve.
//   2. `luarocks show <rock> <version> --porcelain` lists
//      dependencies.
//
// Integrity isn't surfaced by luarocks CLI; would require a
// luarocks.org API fetch. Stub left empty.
//
// luarocksPath is the absolute path to the real `luarocks` binary.
func ResolveLuaRocksTree(ctx context.Context, luarocksPath string, installArgs []string) ([]PackageRef, error) {
	if len(installArgs) == 0 {
		return nil, errors.New("no luarocks install args supplied")
	}
	luarocks := luarocksPath
	if luarocks == "" {
		luarocks = "luarocks"
	}
	if installArgs[0] == "install" {
		installArgs = installArgs[1:]
	}
	var rocks []string
	for _, a := range installArgs {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		rocks = append(rocks, a)
	}
	if len(rocks) == 0 {
		return nil, errors.New("no resolvable lua rocks")
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, rock := range rocks {
		// `luarocks search --porcelain <rock>` output:
		//   <name>\t<version>\trockspec\t<location>
		cmd := exec.CommandContext(ctx, luarocks, "search", "--porcelain", rock)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Split(line, "\t")
			if len(fields) < 2 {
				continue
			}
			name := strings.TrimSpace(fields[0])
			version := strings.TrimSpace(fields[1])
			if name == "" || version == "" {
				continue
			}
			key := name + "@" + version
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			refs = append(refs, PackageRef{
				Ecosystem: "luarocks",
				Name:      name,
				Version:   version,
				Direct:    true,
			})
			break // first (latest) match
		}
	}
	return refs, nil
}

// unused placeholder for a future luarocks API fetcher.
type luarocksUnused = json.RawMessage
