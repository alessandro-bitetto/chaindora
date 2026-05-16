package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveRebar3Tree parses rebar.lock — Erlang/rebar3's pinned
// dep list. Same shape as mix.lock (tuple-style):
//
//	{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.9.0">>},0}.
//	{<<"ranch">>,{pkg,<<"ranch">>,<<"1.8.0">>},1}.
//
// rebar3 keeps content checksums in a separate `1>` block at the
// end of the file:
//
//	[
//	  {pkg_hash,[
//	    {<<"cowboy">>, <<"868CA80BBD0D0F8A98CD9B98D7F1A4CCA3...">>},
//	    ...
//	  ]},
//	  {pkg_hash_ext,[...]}
//	].
//
// rebarPath unused (parser is cwd-only).
func ResolveRebar3Tree(ctx context.Context, rebarPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("rebar3 resolver requires the user's project cwd")
	}
	data, err := os.ReadFile(filepath.Join(cwd, "rebar.lock"))
	if err != nil {
		return nil, fmt.Errorf("read rebar.lock: %w", err)
	}
	return parseRebar3Lock(data), nil
}

func parseRebar3Lock(data []byte) []PackageRef {
	s := string(data)
	// Pull out checksums first so we can attach them by name.
	checksums := map[string]string{}
	if idx := strings.Index(s, "{pkg_hash,["); idx >= 0 {
		block := s[idx+len("{pkg_hash,["):]
		// Each row is `{<<"name">>, <<"HEX">>}`.
		for _, row := range strings.Split(block, "{") {
			row = strings.TrimSpace(row)
			if row == "" || strings.HasPrefix(row, "pkg_hash") {
				continue
			}
			// Extract two <<...>> tokens.
			parts := extractErlangBinaries(row)
			if len(parts) >= 2 {
				checksums[parts[0]] = strings.ToLower(parts[1])
			}
		}
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	// Now walk the top of the file for package entries.
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "{<<") {
			continue
		}
		parts := extractErlangBinaries(trimmed)
		// Shape: name, "pkg" type tag (binary?), name (again), version, level.
		// We want first binary (name) and last binary before the level (version).
		if len(parts) < 2 {
			continue
		}
		name := parts[0]
		// Version is the LAST <<...>> we see in the line before the
		// trailing depth integer.
		version := parts[len(parts)-1]
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if h := checksums[name]; h != "" {
			integrity = "sha256:" + h
		}
		refs = append(refs, PackageRef{
			Ecosystem: "hex",
			Name:      name,
			Version:   version,
			Integrity: integrity,
		})
	}
	return refs
}

// extractErlangBinaries pulls the contents of every `<<"...">>`
// occurrence in s, preserving order.
func extractErlangBinaries(s string) []string {
	var out []string
	for {
		i := strings.Index(s, `<<"`)
		if i < 0 {
			break
		}
		j := strings.Index(s[i+3:], `"`)
		if j < 0 {
			break
		}
		out = append(out, s[i+3:i+3+j])
		s = s[i+3+j+1:]
	}
	return out
}
