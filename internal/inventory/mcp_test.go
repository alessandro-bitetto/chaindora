package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func writeMCP(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestIsKnownMCPConfig(t *testing.T) {
	for _, ok := range []string{"mcp.json", ".mcp.json", "claude_desktop_config.json", "cline_mcp_settings.json", "mcp_settings.json", "mcp_config.json"} {
		if !IsKnownMCPConfig(ok) {
			t.Errorf("%s should be recognized", ok)
		}
	}
	for _, notOK := range []string{"settings.json", "package.json", "config.json", ""} {
		if IsKnownMCPConfig(notOK) {
			t.Errorf("%s should NOT be recognized", notOK)
		}
	}
}

func TestIsGeminiSettingsJSON(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/home/alice/.gemini/settings.json", true},
		{"/home/alice/.vscode/settings.json", false},
		{"/home/alice/.gemini/other.json", false},
		{"settings.json", false}, // missing parent context
	}
	for _, c := range cases {
		if got := IsGeminiSettingsJSON(c.path); got != c.want {
			t.Errorf("IsGeminiSettingsJSON(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestSanitizeRemoteURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"strips path", "https://api.example.com/mcp/some-token/endpoint", "https://api.example.com"},
		{"strips userinfo", "https://user:secret@api.example.com/x", "https://api.example.com"},
		{"strips query", "https://api.example.com/x?token=abc", "https://api.example.com"},
		{"strips fragment", "https://api.example.com/x#frag", "https://api.example.com"},
		{"network-path reference", "//api.example.com/x", "//api.example.com"},
		{"network-path with userinfo", "//user:pass@api.example.com/x", "//api.example.com"},
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"no scheme and no //", "api.example.com/x", ""},
		{"keeps custom scheme", "sse://api.example.com/stream", "sse://api.example.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeRemoteURL(c.in); got != c.want {
				t.Errorf("sanitizeRemoteURL(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestParseMCPConfig_McpServersEnvelope(t *testing.T) {
	p := writeMCP(t, "mcp.json", `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "SECRET-MUST-NOT-LEAK"}
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}`)
	pkgs, err := parseMCPConfig(p)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(pkgs))
	}
	// Sorted by id: "filesystem" < "github"
	if pkgs[0].Name != "@modelcontextprotocol/server-filesystem" {
		t.Errorf("first pkg name: got %q", pkgs[0].Name)
	}
	if pkgs[1].Name != "@modelcontextprotocol/server-github" {
		t.Errorf("second pkg name: got %q", pkgs[1].Name)
	}
	// Ecosystem must be MCP.
	for _, pkg := range pkgs {
		if pkg.Ecosystem != EcosystemMCP {
			t.Errorf("ecosystem %q, want %q", pkg.Ecosystem, EcosystemMCP)
		}
		if pkg.SourcePath != p {
			t.Errorf("source path: got %q, want %q", pkg.SourcePath, p)
		}
		// CRITICAL: no env value should appear in any field.
		for _, field := range []string{pkg.Name, pkg.Version, pkg.PURL, pkg.ResolvedURL} {
			if field != "" && containsSecret(field) {
				t.Errorf("env secret leaked into package field: %q", field)
			}
		}
	}
}

func TestParseMCPConfig_ServersEnvelope(t *testing.T) {
	p := writeMCP(t, "mcp.json", `{
  "servers": {
    "memory": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]}
  }
}`)
	pkgs, err := parseMCPConfig(p)
	if err != nil || len(pkgs) != 1 || pkgs[0].Name != "@modelcontextprotocol/server-memory" {
		t.Errorf("unexpected: err=%v pkgs=%+v", err, pkgs)
	}
}

func TestParseMCPConfig_FlatEnvelope(t *testing.T) {
	p := writeMCP(t, "mcp.json", `{
  "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}
}`)
	pkgs, err := parseMCPConfig(p)
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("err=%v pkgs=%+v", err, pkgs)
	}
}

func TestParseMCPConfig_RemoteServer(t *testing.T) {
	p := writeMCP(t, "mcp.json", `{
  "mcpServers": {
    "linear": {"url": "https://mcp.linear.app/mcp/SECRET-TOKEN-IN-PATH"}
  }
}`)
	pkgs, err := parseMCPConfig(p)
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("err=%v pkgs=%+v", err, pkgs)
	}
	if pkgs[0].ResolvedURL != "https://mcp.linear.app" {
		t.Errorf("URL not sanitized: got %q", pkgs[0].ResolvedURL)
	}
	if pkgs[0].Name != "linear" {
		t.Errorf("remote pkg name should be server id, got %q", pkgs[0].Name)
	}
	if pkgs[0].Version != "" {
		t.Errorf("remote pkg version should be empty, got %q", pkgs[0].Version)
	}
}

func TestParseMCPConfig_DockerLauncher(t *testing.T) {
	p := writeMCP(t, "mcp.json", `{
  "mcpServers": {
    "myserver": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-e", "TOKEN=secret", "myorg/mcp-server:v1.2.3"]
    }
  }
}`)
	pkgs, err := parseMCPConfig(p)
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("err=%v pkgs=%+v", err, pkgs)
	}
	if pkgs[0].Name != "myorg/mcp-server" {
		t.Errorf("docker name: got %q, want %q", pkgs[0].Name, "myorg/mcp-server")
	}
	if pkgs[0].Version != "v1.2.3" {
		t.Errorf("docker tag should become version: got %q", pkgs[0].Version)
	}
}

func TestParseMCPConfig_DockerDigestPin(t *testing.T) {
	p := writeMCP(t, "mcp.json", `{
  "mcpServers": {
    "pinned": {
      "command": "docker",
      "args": ["run", "-i", "myorg/server@sha256:abc123"]
    }
  }
}`)
	pkgs, _ := parseMCPConfig(p)
	if len(pkgs) != 1 {
		t.Fatalf("got %d pkgs", len(pkgs))
	}
	if pkgs[0].Version != "sha256:abc123" {
		t.Errorf("digest pin should land in Version: got %q", pkgs[0].Version)
	}
}

func TestParseMCPConfig_PipInstallLauncher(t *testing.T) {
	p := writeMCP(t, "mcp.json", `{
  "mcpServers": {
    "py-server": {"command": "pip", "args": ["install", "mcp-pkg-name"]}
  }
}`)
	pkgs, _ := parseMCPConfig(p)
	if len(pkgs) != 1 || pkgs[0].Name != "mcp-pkg-name" {
		t.Errorf("expected mcp-pkg-name, got %+v", pkgs)
	}
}

func TestParseMCPConfig_UvxLauncher(t *testing.T) {
	p := writeMCP(t, "mcp.json", `{
  "mcpServers": {
    "uvx-server": {"command": "uvx", "args": ["my-mcp-tool"]}
  }
}`)
	pkgs, _ := parseMCPConfig(p)
	if len(pkgs) != 1 || pkgs[0].Name != "my-mcp-tool" {
		t.Errorf("expected my-mcp-tool, got %+v", pkgs)
	}
}

func TestParseMCPConfig_UvToolRunLauncher(t *testing.T) {
	p := writeMCP(t, "mcp.json", `{
  "mcpServers": {
    "uv-tool": {"command": "uv", "args": ["tool", "run", "my-mcp-tool", "--flag"]}
  }
}`)
	pkgs, _ := parseMCPConfig(p)
	if len(pkgs) != 1 || pkgs[0].Name != "my-mcp-tool" {
		t.Errorf("expected my-mcp-tool, got %+v", pkgs)
	}
}

func TestParseMCPConfig_UnknownLauncherFallsBackToServerID(t *testing.T) {
	p := writeMCP(t, "mcp.json", `{
  "mcpServers": {
    "custom": {"command": "/usr/local/bin/some-binary", "args": ["--listen", "8080"]}
  }
}`)
	pkgs, _ := parseMCPConfig(p)
	if len(pkgs) != 1 || pkgs[0].Name != "custom" {
		t.Errorf("expected server id fallback 'custom', got %+v", pkgs)
	}
}

func TestParseMCPConfig_DropsEntryWithNoCommandOrURL(t *testing.T) {
	p := writeMCP(t, "mcp.json", `{
  "mcpServers": {
    "ghost": {"env": {"X": "y"}}
  }
}`)
	pkgs, _ := parseMCPConfig(p)
	if len(pkgs) != 0 {
		t.Errorf("entry with no command or URL should be dropped, got %+v", pkgs)
	}
}

func TestParseMCPConfig_EmptyFile(t *testing.T) {
	p := writeMCP(t, "mcp.json", "")
	pkgs, err := parseMCPConfig(p)
	if err != nil {
		t.Errorf("empty file should not error, got %v", err)
	}
	if pkgs != nil {
		t.Errorf("empty file should yield nil pkgs, got %+v", pkgs)
	}
}

func TestParseMCPConfig_TooLarge(t *testing.T) {
	huge := make([]byte, 2<<20)
	for i := range huge {
		huge[i] = '{'
	}
	p := filepath.Join(t.TempDir(), "huge.json")
	_ = os.WriteFile(p, huge, 0o644)
	_, err := parseMCPConfig(p)
	if err == nil {
		t.Error("expected error on 2MiB config")
	}
}

func TestParseMCPConfig_DockerSkipsFlagValues(t *testing.T) {
	// -e takes a value, --network takes a value — the image arg
	// comes after those. Verifies we don't accidentally treat
	// "value-of-flag" as the image.
	p := writeMCP(t, "mcp.json", `{
  "mcpServers": {
    "x": {"command": "docker", "args": ["run", "--network", "host", "-e", "FOO=bar", "myimg:latest"]}
  }
}`)
	pkgs, _ := parseMCPConfig(p)
	if len(pkgs) != 1 {
		t.Fatalf("got %d", len(pkgs))
	}
	if pkgs[0].Name != "myimg" || pkgs[0].Version != "latest" {
		t.Errorf("expected myimg:latest, got %q/%q", pkgs[0].Name, pkgs[0].Version)
	}
}

// containsSecret is a defense-in-depth check used in tests. The
// fixtures use the literal "SECRET" string in env values so a leak
// of any env value into an emitted field can be caught.
func containsSecret(s string) bool {
	return len(s) >= len("SECRET") && (s == "SECRET" || stringContains(s, "SECRET"))
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
