package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ResolveGoModTree resolves what `go get` would pull in for the
// supplied modules, including transitives. Approach:
//   1. tmpdir with a minimal go.mod that `require`s every
//      module@version the user asked for.
//   2. `go mod download -json all` fetches every module in the
//      transitive graph and writes one JSON object per line to
//      stdout. No code is executed; only module bytes are
//      fetched (and verified against sumdb by the Go tooling
//      itself).
//   3. Parse each line and emit a PackageRef.
//
// goPath is the absolute path to the real `go` binary so the
// shim can't loop. We use GONOSUMCHECK only to avoid the
// resolver failing when a module's checksum isn't in the
// local cache (sum.golang.org still answers, the gate's own
// provenance checker verifies sumdb).
func ResolveGoModTree(ctx context.Context, goPath string, args []string) ([]PackageRef, error) {
	if len(args) == 0 {
		return nil, errors.New("no go module args supplied")
	}
	goBin := goPath
	if goBin == "" {
		goBin = "go"
	}
	mods, err := parseGoModArgs(args)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-go-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	var goMod strings.Builder
	goMod.WriteString("module chdora.gate.resolve\n\ngo 1.22\n\nrequire (\n")
	for _, m := range mods {
		fmt.Fprintf(&goMod, "\t%s %s\n", m.module, m.version)
	}
	goMod.WriteString(")\n")
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte(goMod.String()), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(tmp, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, goBin, "mod", "download", "-json", "all")
	cmd.Dir = tmp
	// Use a fresh GOPATH so the resolver doesn't pollute the
	// user's module cache. GOMODCACHE inherits GOPATH.
	cmd.Env = append(os.Environ(),
		"GOPATH="+filepath.Join(tmp, "gopath"),
		"GOFLAGS=-mod=mod",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		snippet := strings.TrimSpace(stderr.String())
		if len(snippet) > 400 {
			snippet = snippet[:400] + "..."
		}
		return nil, fmt.Errorf("go mod download -json all failed: %w\n%s", err, snippet)
	}
	return parseGoModDownloadJSON(stdout.Bytes(), mods)
}

type goModArg struct {
	module  string
	version string
}

// parseGoModArgs accepts `module@version` (the standard
// `go get` form). Bare module names default to `@latest`,
// resolved by the resolver itself.
func parseGoModArgs(args []string) ([]goModArg, error) {
	var out []goModArg
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		dep := goModArg{module: a, version: "latest"}
		// Find the version separator. Module paths can contain
		// slashes but never '@', so the FIRST '@' is the
		// separator.
		if i := strings.Index(a, "@"); i > 0 {
			dep.module = a[:i]
			dep.version = a[i+1:]
		}
		out = append(out, dep)
	}
	if len(out) == 0 {
		return nil, errors.New("no resolvable go modules in args")
	}
	return out, nil
}

// parseGoModDownloadJSON parses `go mod download -json all`
// output. Each line is a JSON object describing one fetched
// module. We filter to actual modules (Error field empty,
// Version non-zero) and skip our synthetic root.
func parseGoModDownloadJSON(data []byte, directs []goModArg) ([]PackageRef, error) {
	directSet := map[string]struct{}{}
	for _, d := range directs {
		directSet[d.module] = struct{}{}
	}
	// `go mod download -json` emits a stream of JSON objects
	// separated by newlines (occasionally bare {} too). Use a
	// decoder that consumes objects until EOF.
	dec := json.NewDecoder(bytes.NewReader(data))
	var refs []PackageRef
	seen := map[string]struct{}{}
	for {
		var entry struct {
			Path    string `json:"Path"`
			Version string `json:"Version"`
			Error   string `json:"Error"`
		}
		if err := dec.Decode(&entry); err != nil {
			break
		}
		if entry.Error != "" {
			continue
		}
		if entry.Path == "" || entry.Version == "" {
			continue
		}
		if entry.Path == "chdora.gate.resolve" {
			continue
		}
		ident := entry.Path + "@" + entry.Version
		if _, dup := seen[ident]; dup {
			continue
		}
		seen[ident] = struct{}{}
		_, isDirect := directSet[entry.Path]
		refs = append(refs, PackageRef{
			Ecosystem: "go",
			Name:      entry.Path,
			Version:   entry.Version,
			Direct:    isDirect,
		})
	}
	return refs, nil
}
