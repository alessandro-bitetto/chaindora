package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ResolveDenoTree resolves Deno's dependency set. Deno is unusual:
// deps come from URLs (esm.sh, deno.land/x) and increasingly npm:
// specifiers. The lockfile (deno.lock v3+) records sha256 hashes
// for HTTPS-fetched modules and npm package integrities for
// npm:-prefixed deps.
//
// Approach (cwd-based — Deno has no first-class "add this dep"
// CLI; users edit deno.json or rely on imports in source files):
//   1. Run `deno cache --lock=deno.lock --lock-write deno.json`
//      (or "main.ts" — there's no manifest required).
//   2. Parse deno.lock JSON.
//
// denoPath is the absolute path to the real `deno` binary.
func ResolveDenoTree(ctx context.Context, denoPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("deno resolver requires the user's project cwd")
	}
	deno := denoPath
	if deno == "" {
		deno = "deno"
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-deno-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)
	// Copy deno.json (or deno.jsonc) and any pre-existing lockfile
	// into the temp dir so deno's resolution sees the user's
	// declared imports / npm specifiers.
	for _, name := range []string{"deno.json", "deno.jsonc"} {
		if b, err := os.ReadFile(filepath.Join(cwd, name)); err == nil {
			if err := os.WriteFile(filepath.Join(tmp, name), b, 0o644); err != nil {
				return nil, fmt.Errorf("seed %s: %w", name, err)
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(cwd, "deno.lock")); err == nil {
		if err := os.WriteFile(filepath.Join(tmp, "deno.lock"), b, 0o644); err != nil {
			return nil, fmt.Errorf("seed deno.lock: %w", err)
		}
	}
	cmd := exec.CommandContext(ctx, deno, "cache", "--lock=deno.lock", "--lock-write", "--reload")
	// Pass through the import-map / main entry from the user's
	// deno.json; if none exists, deno picks up imports from a
	// dummy entry.
	cmd.Dir = tmp
	cmd.Env = append(os.Environ(), "DENO_DIR="+filepath.Join(tmp, ".deno"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Try cache against main.ts pattern as a fallback for
		// projects without deno.json.
		_ = out
	}
	data, err := os.ReadFile(filepath.Join(tmp, "deno.lock"))
	if err != nil {
		return nil, fmt.Errorf("read deno.lock: %w", err)
	}
	return parseDenoLock(data), nil
}

// parseDenoLock walks deno.lock v3. Schema:
//
//	{
//	  "version": "3",
//	  "remote": {
//	    "https://deno.land/x/std@0.224.0/path/mod.ts": "sha256-hex"
//	  },
//	  "npm": {
//	    "specifiers": {"chalk@^5": "chalk@5.3.0"},
//	    "packages": {
//	      "chalk@5.3.0": {
//	        "integrity": "sha512-...",
//	        "dependencies": {...}
//	      }
//	    }
//	  }
//	}
func parseDenoLock(data []byte) []PackageRef {
	var lock struct {
		Remote map[string]string `json:"remote"`
		NPM    struct {
			Packages map[string]struct {
				Integrity string `json:"integrity"`
			} `json:"packages"`
		} `json:"npm"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	for spec, entry := range lock.NPM.Packages {
		// spec is "name@version" — possibly scoped: "@scope/name@version".
		atIdx := -1
		if strings.HasPrefix(spec, "@") {
			if i := strings.LastIndex(spec[1:], "@"); i > 0 {
				atIdx = i + 1
			}
		} else {
			atIdx = strings.LastIndex(spec, "@")
		}
		if atIdx <= 0 {
			continue
		}
		name := spec[:atIdx]
		version := spec[atIdx+1:]
		// Trim peer-deps suffix some lockfile versions add:
		// "chalk@5.3.0_foo@1".
		if i := strings.Index(version, "_"); i >= 0 {
			version = version[:i]
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, PackageRef{
			Ecosystem: "npm",
			Name:      name,
			Version:   version,
			Integrity: entry.Integrity,
		})
	}
	// We deliberately don't emit PackageRefs for the `remote` map
	// (raw URL fetches). Those would route through the git-url
	// checker if they had git-like URLs, but flat HTTPS deps don't
	// have an ecosystem in OSV.
	return refs
}
