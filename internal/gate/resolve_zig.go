package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveZigTree parses build.zig.zon — Zig's dependency manifest
// (since Zig 0.11). Format is Zig's Object Notation:
//
//	.{
//	    .name = "myapp",
//	    .version = "0.1.0",
//	    .dependencies = .{
//	        .libfoo = .{
//	            .url = "https://...",
//	            .hash = "12200abc...",
//	        },
//	    },
//	}
//
// Each dep's hash is content-addressed by Zig's package system —
// a self-describing multihash. We use it directly as integrity.
//
// zigPath unused (parser is cwd-only).
func ResolveZigTree(ctx context.Context, zigPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("zig resolver requires the user's project cwd")
	}
	data, err := os.ReadFile(filepath.Join(cwd, "build.zig.zon"))
	if err != nil {
		return nil, fmt.Errorf("read build.zig.zon: %w", err)
	}
	return parseZigZon(data), nil
}

// parseZigZon walks the ZON document looking for `.dependencies = .{ ... }`
// and extracts each named dep with url + hash + optional version.
func parseZigZon(data []byte) []PackageRef {
	s := string(data)
	idx := strings.Index(s, ".dependencies")
	if idx < 0 {
		return nil
	}
	// Find the opening brace after .dependencies = .{ }.
	openBrace := strings.Index(s[idx:], "{")
	if openBrace < 0 {
		return nil
	}
	// Find matching close brace.
	depth := 0
	end := -1
	for i := idx + openBrace; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i
				break
			}
		}
		if end != -1 {
			break
		}
	}
	if end <= idx+openBrace {
		return nil
	}
	depsBlock := s[idx+openBrace+1 : end]
	// Each dep is `.<name> = .{ .url = "..."?, .hash = "..." },`
	// Split on ".<ident> = .{".
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, chunk := range strings.Split(depsBlock, ".{") {
		// Find name in the bit BEFORE this chunk start: ". <name> = "
		// Simpler approach: parse each line of depsBlock looking for
		// `.<name> = .{` markers manually.
		_ = chunk
	}
	// Linear scan approach.
	lines := strings.Split(depsBlock, "\n")
	var currentName, currentHash, currentVersion string
	flush := func() {
		defer func() { currentName, currentHash, currentVersion = "", "", "" }()
		if currentName == "" || currentHash == "" {
			return
		}
		if currentVersion == "" {
			currentVersion = "zig-content-addressed"
		}
		key := currentName + "@" + currentVersion
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		refs = append(refs, PackageRef{
			Ecosystem: "zig",
			Name:      currentName,
			Version:   currentVersion,
			Integrity: "zig:" + currentHash,
		})
	}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Start of a new dep: `.<name> = .{`
		if strings.HasPrefix(trimmed, ".") && strings.Contains(trimmed, "= .{") {
			flush()
			eq := strings.Index(trimmed, "=")
			currentName = strings.TrimSpace(strings.TrimPrefix(trimmed[:eq], "."))
			continue
		}
		// Hash field: `.hash = "...",`
		if strings.HasPrefix(trimmed, ".hash") {
			if q1 := strings.Index(trimmed, `"`); q1 >= 0 {
				rest := trimmed[q1+1:]
				if q2 := strings.Index(rest, `"`); q2 >= 0 {
					currentHash = rest[:q2]
				}
			}
		}
		if strings.HasPrefix(trimmed, ".version") {
			if q1 := strings.Index(trimmed, `"`); q1 >= 0 {
				rest := trimmed[q1+1:]
				if q2 := strings.Index(rest, `"`); q2 >= 0 {
					currentVersion = rest[:q2]
				}
			}
		}
		// End of dep: `}`
		if trimmed == "}," || trimmed == "}" {
			flush()
		}
	}
	flush()
	return refs
}
