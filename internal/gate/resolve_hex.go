package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ResolveHexTree resolves the Elixir / Erlang dep set declared in
// the user's mix.exs. Mix doesn't have a "add this dep" CLI —
// users edit mix.exs and run `mix deps.get` / `mix deps.update`.
// The gate intercepts those verbs.
//
// Implementation: copy mix.exs + mix.lock into a temp dir, run
// `mix deps.get --check-locked` there, parse the resulting
// mix.lock. Hex packages don't run code at fetch time, so this
// is safe.
//
// mixPath is the absolute path to the real `mix` binary; cwd is
// the user's project directory.
func ResolveHexTree(ctx context.Context, mixPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("hex resolver requires the user's project cwd")
	}
	mix := mixPath
	if mix == "" {
		mix = "mix"
	}
	mixExs, err := os.ReadFile(filepath.Join(cwd, "mix.exs"))
	if err != nil {
		return nil, fmt.Errorf("read mix.exs in %s: %w", cwd, err)
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-mix-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)
	if err := os.WriteFile(filepath.Join(tmp, "mix.exs"), mixExs, 0o644); err != nil {
		return nil, fmt.Errorf("seed mix.exs: %w", err)
	}
	if lockBytes, err := os.ReadFile(filepath.Join(cwd, "mix.lock")); err == nil {
		if err := os.WriteFile(filepath.Join(tmp, "mix.lock"), lockBytes, 0o644); err != nil {
			return nil, fmt.Errorf("seed mix.lock: %w", err)
		}
	}
	// `mix deps.get` fetches packages but doesn't compile them.
	// Hex package fetch is a simple HTTPS tarball download — no
	// code execution at this stage.
	cmd := exec.CommandContext(ctx, mix, "deps.get")
	cmd.Dir = tmp
	cmd.Env = append(os.Environ(),
		"MIX_ENV=prod",
		"MIX_HOME="+filepath.Join(tmp, "mix-home"),
		"HEX_HOME="+filepath.Join(tmp, "hex-home"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapPMError("mix", "deps.get", out, err)
	}
	data, err := os.ReadFile(filepath.Join(tmp, "mix.lock"))
	if err != nil {
		return nil, fmt.Errorf("read mix.lock: %w", err)
	}
	return parseMixLockTree(data), nil
}

// parseMixLockTree extracts (name, version, checksum) tuples
// from mix.lock. The format is Elixir map literal syntax:
//
//	%{
//	  "phoenix": {:hex, :phoenix, "1.7.10", "abc...", [], [...], "hexpm", "def..."},
//	  ...
//	}
//
// Tuple positions (for :hex source):
//
//	0: source atom (:hex)
//	1: package name atom
//	2: version
//	3: inner checksum (Hex.Tar inner)
//	4: build tools
//	5: deps
//	6: repo (e.g. "hexpm")
//	7: outer checksum (sha256 of the tarball — what we want)
//
// We extract positions 2 (version) and 7 (outer sha256) per entry.
func parseMixLockTree(data []byte) []PackageRef {
	seen := map[string]struct{}{}
	var refs []PackageRef
	// Tokenize by lines; one package per line in normal formatting.
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		// Lines look like: `"phoenix": {:hex, :phoenix, "1.7.10",
		// "checksum_inner", [...], [...], "hexpm", "checksum_outer"},`
		if !strings.HasPrefix(trimmed, `"`) {
			continue
		}
		colon := strings.Index(trimmed, `":`)
		if colon < 0 {
			continue
		}
		name := strings.Trim(trimmed[:colon+1], `"`)
		rest := strings.TrimSpace(trimmed[colon+2:])
		if !strings.HasPrefix(rest, "{:hex,") {
			continue // git / path source; skip
		}
		// Strip braces and split on commas-not-inside-brackets.
		body := strings.TrimSuffix(strings.TrimPrefix(rest, "{"), "},")
		body = strings.TrimSuffix(body, "}")
		fields := splitMixTupleFields(body)
		if len(fields) < 3 {
			continue
		}
		version := strings.Trim(strings.TrimSpace(fields[2]), `"`)
		// Outer checksum is the LAST quoted string in the tuple
		// (position varies across mix versions; safest to grab
		// the last "..."-bounded field).
		outerSHA := ""
		for i := len(fields) - 1; i >= 3; i-- {
			f := strings.TrimSpace(fields[i])
			if strings.HasPrefix(f, `"`) && strings.HasSuffix(f, `"`) {
				outerSHA = strings.Trim(f, `"`)
				break
			}
		}
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if outerSHA != "" && isHex(strings.ToLower(outerSHA)) && len(outerSHA) >= 32 {
			integrity = "sha256:" + strings.ToLower(outerSHA)
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

// splitMixTupleFields splits on commas at the top level only —
// commas inside `[...]` or `{...}` (deps list, etc.) are kept
// together with their containing field.
func splitMixTupleFields(s string) []string {
	var fields []string
	depth := 0
	start := 0
	for i, c := range s {
		switch c {
		case '[', '{', '(':
			depth++
		case ']', '}', ')':
			depth--
		case ',':
			if depth == 0 {
				fields = append(fields, s[start:i])
				start = i + 1
			}
		}
	}
	if start < len(s) {
		fields = append(fields, s[start:])
	}
	return fields
}
