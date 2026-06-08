package inventory

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MCP (Model Context Protocol) host-config parser. Reads the JSON
// config files that MCP clients (Claude Desktop, mcp.json, .mcp.json,
// Cline, Gemini settings) use to declare configured servers, and
// emits one inventory.Package per configured server.
//
// Design lineage: borrowed conceptually from perplexityai/bumblebee's
// MCP scanner (BSD-licensed). The wire shape, sanitization rules,
// and "drop env values" posture are theirs; the inventory.Package
// mapping is chaindora-side.
//
// Why this is in inventory and not in detectors: an MCP server is a
// package-ish thing — it has a launcher (npm, pypi, uv, docker) and
// a spec ("@modelcontextprotocol/server-github") that points back to
// the underlying registry. Surfacing those at the inventory layer
// lets the existing detectors (incident-pack, osvioc, predictive)
// fire against MCP server packages with no extra wiring beyond the
// ecosystem→OSV mapping (which today is empty — see comment on
// EcosystemMCP in inventory.go).
//
// Security boundaries enforced by this parser:
//   - Env values are NEVER captured (keys aren't either, since the
//     Package struct has no free-form notes field).
//   - Remote URLs are sanitized to scheme+host only — userinfo,
//     query, fragment, and path are dropped because tokens are
//     commonly embedded in any of those (including "/mcp/<token>"
//     path segments). If parsing fails, the URL is dropped entirely
//     rather than emitting a raw, potentially secret-bearing string.

// IsKnownMCPConfig reports whether base is a recognized MCP config
// basename. The inventory dispatcher uses this to dispatch.
func IsKnownMCPConfig(base string) bool {
	switch base {
	case "mcp.json",
		"claude_desktop_config.json",
		"mcp_config.json",
		"mcp_settings.json",
		"cline_mcp_settings.json",
		".mcp.json":
		return true
	}
	return false
}

// IsGeminiSettingsJSON reports whether path is the Gemini CLI / Code
// Assist user settings file (`<home>/.gemini/settings.json`). Dispatch
// is path-aware rather than basename-aware because `settings.json` is
// a common, ambiguous filename (notably VS Code's user settings) that
// we must not feed to the MCP parser globally. The file's top-level
// `mcpServers` envelope is handled by ParseMCPConfig.
func IsGeminiSettingsJSON(path string) bool {
	return filepath.Base(path) == "settings.json" &&
		filepath.Base(filepath.Dir(path)) == ".gemini"
}

// mcpServerEntry is one server config in any of the three envelope
// shapes ({"mcpServers":...}, {"servers":...}, flat). Fields beyond
// these are deliberately ignored — capturing env values, headers, or
// auth material is a security regression.
type mcpServerEntry struct {
	Command   string         `json:"command"`
	Args      []string       `json:"args"`
	Env       map[string]any `json:"env"` // declared but never read
	URL       string         `json:"url"`
	ServerURL string         `json:"serverUrl"`
	HTTPURL   string         `json:"httpUrl"`
	Type      string         `json:"type"`
}

// remoteURL returns the first non-empty remote URL field. Multiple
// clients use different field names for the same thing.
func (e mcpServerEntry) remoteURL() string {
	switch {
	case e.URL != "":
		return e.URL
	case e.ServerURL != "":
		return e.ServerURL
	case e.HTTPURL != "":
		return e.HTTPURL
	}
	return ""
}

// sanitizeRemoteURL returns scheme://host only, or "" if parsing
// fails or no host can be recovered. Tokens commonly live in
// userinfo / query / fragment / path; the conservative move is to
// drop them all rather than risk leaking a credential into an
// inventory record.
func sanitizeRemoteURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	// Scheme-less network-path reference ("//host/path").
	if strings.HasPrefix(u, "//") {
		parsed, err := url.Parse("https:" + u)
		if err != nil || parsed.Host == "" {
			return ""
		}
		return "//" + parsed.Hostname()
	}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return ""
	}
	scheme := parsed.Scheme
	if scheme == "" {
		return ""
	}
	return scheme + "://" + parsed.Hostname()
}

// parseMCPConfig reads a JSON config and returns one inventory.Package
// per configured server. Envelope detection: try {"mcpServers":...}
// first (most common), then {"servers":...}, then flat. Empty file or
// no servers → returns (nil, nil), not an error.
func parseMCPConfig(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	// Bounded parse: a single MCP config shouldn't exceed a few hundred
	// KB. If it does, something is suspicious — bail rather than chew
	// arbitrary input.
	if len(data) > 1<<20 {
		return nil, errors.New("mcp config too large to parse safely (>1MiB)")
	}

	servers, err := extractServers(data)
	if err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		return nil, nil
	}

	// Stable output order — map iteration in Go is randomized.
	ids := make([]string, 0, len(servers))
	for id := range servers {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var out []Package
	for _, id := range ids {
		entry := servers[id]
		pkg := mcpEntryToPackage(id, entry, path)
		if pkg.Name == "" {
			// Drop entries we couldn't extract a meaningful name
			// from rather than emit confusing records.
			continue
		}
		out = append(out, pkg)
	}
	return out, nil
}

// extractServers returns the per-id server map from any of the three
// envelope shapes. Order tried:
//  1. {"mcpServers": {...}} — Claude Desktop, mcp.json, most common
//  2. {"servers": {...}}    — some clients
//  3. {"<id>": {...}}        — flat (every top-level key is a server)
func extractServers(data []byte) (map[string]mcpServerEntry, error) {
	// Try envelope 1.
	var env1 struct {
		MCPServers map[string]mcpServerEntry `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &env1); err == nil && len(env1.MCPServers) > 0 {
		return env1.MCPServers, nil
	}
	// Try envelope 2.
	var env2 struct {
		Servers map[string]mcpServerEntry `json:"servers"`
	}
	if err := json.Unmarshal(data, &env2); err == nil && len(env2.Servers) > 0 {
		return env2.Servers, nil
	}
	// Try flat — but only if the top level looks like server entries
	// (each value has at least one of command / url / serverUrl /
	// httpUrl). Otherwise we'd happily ingest random JSON.
	var flat map[string]mcpServerEntry
	if err := json.Unmarshal(data, &flat); err != nil {
		return nil, nil
	}
	out := map[string]mcpServerEntry{}
	for id, e := range flat {
		if e.Command == "" && e.URL == "" && e.ServerURL == "" && e.HTTPURL == "" {
			continue
		}
		out[id] = e
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// mcpEntryToPackage builds the inventory.Package for one configured
// server. The Name is derived as:
//
//   - Remote launcher (no command, has URL) → the configured server id.
//     Version is empty (no version concept for remote endpoints).
//     ResolvedURL carries the sanitized scheme://host.
//   - Docker launcher (`docker run image:tag`) → Name is the image
//     ref minus the tag, Version is the tag.
//   - npx / pip / pipx / uvx launcher → Name is the first non-flag
//     positional arg after the launcher (the package spec); Version
//     is left empty (npm-style specs are name-only in MCP configs).
//   - Anything else → the configured server id as Name.
//
// SourcePath is the config file. PURL is built via PURL() for the
// EcosystemMCP type — opaque but consistent across emitters.
func mcpEntryToPackage(id string, e mcpServerEntry, sourcePath string) Package {
	pkg := Package{
		Ecosystem:  EcosystemMCP,
		SourcePath: sourcePath,
	}

	// Remote launcher path.
	if e.Command == "" {
		if remote := e.remoteURL(); remote != "" {
			pkg.Name = id
			pkg.ResolvedURL = sanitizeRemoteURL(remote)
			pkg.PURL = PURL(EcosystemMCP, id, "")
			return pkg
		}
		// No command and no URL — not a meaningful MCP server entry.
		return Package{}
	}

	// Launcher-specific extraction.
	name, version := extractPackageFromLauncher(e.Command, e.Args)
	if name == "" {
		// Fall back to the configured server id rather than dropping.
		name = id
	}
	pkg.Name = name
	pkg.Version = version
	pkg.PURL = PURL(EcosystemMCP, name, version)
	return pkg
}

// extractPackageFromLauncher returns (name, version) inferred from
// a launcher command + args. Recognized launchers:
//
//	npx -y @scope/pkg              → ("@scope/pkg", "")
//	npx -y -- @scope/pkg           → ("@scope/pkg", "")
//	npm exec -y -- pkg             → ("pkg", "")
//	pip install pkg                → ("pkg", "")
//	pipx run pkg                   → ("pkg", "")
//	uv tool run pkg                → ("pkg", "")
//	uvx pkg                        → ("pkg", "")
//	docker run -i image:tag        → ("image", "tag")
//	docker run -i registry/img:tag → ("registry/img", "tag")
//
// Returns ("", "") when the launcher isn't recognized — the caller
// then falls back to the server id.
func extractPackageFromLauncher(command string, args []string) (name, version string) {
	cmd := filepath.Base(command)
	switch cmd {
	case "npx":
		return firstNonFlagArg(args), ""
	case "npm":
		// "npm exec -- pkg" or "npm exec -y pkg"
		if len(args) >= 2 && args[0] == "exec" {
			return firstNonFlagArg(args[1:]), ""
		}
		return firstNonFlagArg(args), ""
	case "pipx":
		// "pipx run pkg" or "pipx run --spec pkg cmd"
		if len(args) >= 1 && args[0] == "run" {
			return firstNonFlagArg(args[1:]), ""
		}
		return firstNonFlagArg(args), ""
	case "pip", "pip3":
		// "pip install pkg"
		if len(args) >= 2 && args[0] == "install" {
			return firstNonFlagArg(args[1:]), ""
		}
		return "", ""
	case "uvx":
		return firstNonFlagArg(args), ""
	case "uv":
		// "uv tool run pkg" / "uv run pkg"
		if len(args) >= 1 {
			switch args[0] {
			case "tool":
				if len(args) >= 2 && args[1] == "run" {
					return firstNonFlagArg(args[2:]), ""
				}
			case "run":
				return firstNonFlagArg(args[1:]), ""
			}
		}
	case "docker":
		// "docker run [flags...] image[:tag]" — find the first
		// non-flag arg after "run" that doesn't take a value.
		if len(args) >= 1 && args[0] == "run" {
			ref := dockerImageArg(args[1:])
			if ref != "" {
				return splitDockerRef(ref)
			}
		}
	}
	return "", ""
}

// firstNonFlagArg returns the first arg that isn't a flag. Skips
// "--" separator. Args with "=" in them are treated as flags (e.g.
// "--foo=bar"). Bare "-y", "-n" etc. are flags.
func firstNonFlagArg(args []string) string {
	for _, a := range args {
		if a == "" || a == "--" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

// dockerImageArg returns the image ref from `docker run` args.
// Walks the args skipping flag values for known value-taking flags.
// Not exhaustive — covers the patterns seen in real MCP configs.
func dockerImageArg(args []string) string {
	valueTaking := map[string]bool{
		"-e": true, "--env": true,
		"-v": true, "--volume": true,
		"-p": true, "--publish": true,
		"--name":          true,
		"--network":       true,
		"--mount":         true,
		"--user":          true,
		"-w":              true,
		"--workdir":       true,
		"--entrypoint":    true,
		"--platform":      true,
		"--add-host":      true,
		"--log-driver":    true,
		"--restart":       true,
		"--cap-add":       true,
		"--cap-drop":      true,
		"--security-opt":  true,
		"--label":         true,
		"-l":              true,
		"--ulimit":        true,
	}
	skip := 0
	for i, a := range args {
		if skip > 0 {
			skip--
			continue
		}
		if a == "--" {
			continue
		}
		if !strings.HasPrefix(a, "-") {
			return a
		}
		// "--flag=value" doesn't consume next arg
		if strings.Contains(a, "=") {
			continue
		}
		if valueTaking[a] {
			skip = 1
		}
		_ = i
	}
	return ""
}

// splitDockerRef splits "registry/image:tag" or "image:tag" into
// (name-with-registry, tag). "image" with no tag returns ("image", "").
// "image@sha256:..." returns ("image", "sha256:...") so digest pins
// look like version pins to downstream consumers.
func splitDockerRef(ref string) (name, tag string) {
	// Digest form (image@sha256:hex)
	if at := strings.LastIndex(ref, "@"); at > 0 {
		return ref[:at], ref[at+1:]
	}
	// Tag form. ":" can appear in registry:port — only the LAST
	// colon-separated component is the tag, and only if it doesn't
	// look like a port number.
	if colon := strings.LastIndex(ref, ":"); colon > 0 {
		candidate := ref[colon+1:]
		// "host:5000/image" has no tag.
		if !strings.Contains(candidate, "/") {
			return ref[:colon], candidate
		}
	}
	return ref, ""
}
