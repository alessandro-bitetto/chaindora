package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// `chdora agent` is the client side of fleet mode. Three
// subcommands:
//   enroll  — register this machine with the server, save token
//   push    — upload a findings JSON to the server
//   status  — show what this agent is registered as

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Fleet-mode client: enroll, push findings, status",
	Long: `chdora agent is the client side of fleet mode. It pairs with
chdora server (v0.13+) for multi-machine view.

Workflow:

  # Once per machine
  chdora agent enroll --server URL --name laptop-alice [--enrollment-secret X]

  # After each scan
  chdora audit --format json > findings.json
  chdora agent push --findings findings.json

  # Or hook into watch
  chdora watch --server URL`,
}

var (
	agentConfigPath  string
	agentServer      string
	agentName        string
	agentEnrollSec   string
	agentFindingsArg string
)

// agentConfig persists per-machine state: server URL, agent ID,
// bearer token. Stored at ~/.chaindora/agent.json.
type agentConfig struct {
	ServerURL string `json:"server_url"`
	AgentID   string `json:"agent_id"`
	APIKey    string `json:"api_key"`
	Name      string `json:"name"`
}

func defaultAgentConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".chaindora", "agent.json")
}

func loadAgentConfig(path string) (*agentConfig, error) {
	if path == "" {
		path = defaultAgentConfigPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var c agentConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func saveAgentConfig(path string, c *agentConfig) error {
	if path == "" {
		path = defaultAgentConfigPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// 0o600 — the api_key is bearer-token credential material.
	return os.WriteFile(path, data, 0o600)
}

var agentEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Register this machine with a chdora server and save the API token",
	RunE: func(cmd *cobra.Command, args []string) error {
		if agentServer == "" {
			return errors.New("--server URL is required")
		}
		if agentName == "" {
			h, _ := os.Hostname()
			agentName = h
			if agentName == "" {
				return errors.New("--name is required (couldn't detect hostname)")
			}
		}
		hostname, _ := os.Hostname()
		body := map[string]string{
			"name":           agentName,
			"hostname":       hostname,
			"chdora_version": Version,
		}
		buf, _ := json.Marshal(body)
		req, err := http.NewRequest(http.MethodPost, strings.TrimRight(agentServer, "/")+"/api/v1/agents/enroll", bytes.NewReader(buf))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if agentEnrollSec != "" {
			req.Header.Set("X-Chaindora-Enroll-Secret", agentEnrollSec)
		}
		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("enroll: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			return fmt.Errorf("enroll: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
		}
		var out struct {
			AgentID    string `json:"agent_id"`
			APIKey     string `json:"api_key"`
			EnrolledAt string `json:"enrolled_at"`
			ServerNote string `json:"server_note"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return err
		}
		c := &agentConfig{
			ServerURL: agentServer,
			AgentID:   out.AgentID,
			APIKey:    out.APIKey,
			Name:      agentName,
		}
		if err := saveAgentConfig(agentConfigPath, c); err != nil {
			fmt.Fprintf(os.Stderr, "warn: failed to save %s: %v\n", agentConfigPath, err)
			fmt.Fprintln(os.Stderr, "Persist these yourself — the api_key won't be shown again:")
			fmt.Fprintf(os.Stderr, "  agent_id: %s\n", out.AgentID)
			fmt.Fprintf(os.Stderr, "  api_key:  %s\n", out.APIKey)
			return err
		}
		path := agentConfigPath
		if path == "" {
			path = defaultAgentConfigPath()
		}
		fmt.Fprintf(os.Stderr, "[chdora agent] enrolled as %s (id %s)\n", agentName, out.AgentID)
		fmt.Fprintf(os.Stderr, "[chdora agent] credentials saved to %s (mode 0600)\n", path)
		return nil
	},
}

var agentPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Upload a findings JSON file to the configured server",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := loadAgentConfig(agentConfigPath)
		if err != nil {
			return err
		}
		if c == nil {
			return errors.New("not enrolled — run `chdora agent enroll` first")
		}
		if agentFindingsArg == "" {
			return errors.New("--findings <path> is required")
		}
		data, err := os.ReadFile(agentFindingsArg)
		if err != nil {
			return fmt.Errorf("read findings: %w", err)
		}
		var fs []findings.Finding
		if err := json.Unmarshal(data, &fs); err != nil {
			return fmt.Errorf("parse findings JSON: %w", err)
		}
		// agent push is uploading findings the user already
		// produced on disk; the run that generated them is in the
		// past and presumed complete (the user wouldn't be
		// running `agent push` on a half-written file). Construct
		// a complete-status summary so the server can tell us
		// apart from older agents that send no summary at all.
		summary := findings.NewCompleteSummary(time.Now().UTC(), len(fs), strings.Join(os.Args, " "), Version)
		scanID, err := pushFindingsToServer(c, fs, strings.Join(os.Args, " "), &summary)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "[chdora agent] uploaded %d finding(s) — scan_id %s\n", len(fs), scanID)
		return nil
	},
}

// pushFindingsToServer is the shared upload helper used by both
// `chdora agent push` and the in-process watch integration. summary is
// optional: nil signals "this push happened but we don't have an
// explicit summary record" and the server treats it as complete for
// back-compat with v0.16-and-earlier agents. Callers that DO know the
// run completed cleanly should pass a non-nil summary so the server
// can distinguish them from partial/error runs going forward.
func pushFindingsToServer(c *agentConfig, fs []findings.Finding, command string, summary *findings.ScanSummary) (string, error) {
	if c == nil || c.ServerURL == "" || c.AgentID == "" || c.APIKey == "" {
		return "", errors.New("agent config missing server_url / agent_id / api_key")
	}
	body := map[string]any{
		"command":        command,
		"chdora_version": Version,
		"findings":       fs,
	}
	if summary != nil {
		body["summary"] = summary
	}
	buf, _ := json.Marshal(body)
	url := fmt.Sprintf("%s/api/v1/agents/%s/scan",
		strings.TrimRight(c.ServerURL, "/"), c.AgentID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("push: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("push: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	var out struct {
		ScanID string `json:"scan_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.ScanID, nil
}

var agentStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the local agent's enrollment status",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := loadAgentConfig(agentConfigPath)
		if err != nil {
			return err
		}
		path := agentConfigPath
		if path == "" {
			path = defaultAgentConfigPath()
		}
		if c == nil {
			fmt.Fprintf(os.Stderr, "not enrolled (no config at %s)\n", path)
			return nil
		}
		fmt.Fprintf(os.Stderr, "config:    %s\n", path)
		fmt.Fprintf(os.Stderr, "server:    %s\n", c.ServerURL)
		fmt.Fprintf(os.Stderr, "agent id:  %s\n", c.AgentID)
		fmt.Fprintf(os.Stderr, "name:      %s\n", c.Name)
		fmt.Fprintf(os.Stderr, "api key:   %s…%s (hashed on server)\n",
			c.APIKey[:8], c.APIKey[len(c.APIKey)-4:])

		// Probe the server with GET /healthz.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
			strings.TrimRight(c.ServerURL, "/")+"/healthz", nil)
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "server:    UNREACHABLE (%v)\n", err)
			return nil
		}
		defer resp.Body.Close()
		fmt.Fprintf(os.Stderr, "server:    reachable (HTTP %d)\n", resp.StatusCode)
		return nil
	},
}

func init() {
	agentCmd.PersistentFlags().StringVar(&agentConfigPath, "config", "", "path to agent config (default: ~/.chaindora/agent.json)")

	agentEnrollCmd.Flags().StringVar(&agentServer, "server", "", "chdora server URL, e.g. https://chaindora.corp:8080 (required)")
	agentEnrollCmd.Flags().StringVar(&agentName, "name", "", "this agent's display name (default: $HOSTNAME)")
	agentEnrollCmd.Flags().StringVar(&agentEnrollSec, "enrollment-secret", "", "the server's enrollment secret (required if the server is configured with one)")
	_ = agentEnrollCmd.MarkFlagRequired("server")

	agentPushCmd.Flags().StringVar(&agentFindingsArg, "findings", "", "path to a findings JSON file (produced by --format json on scan/ci/forensics/audit)")
	_ = agentPushCmd.MarkFlagRequired("findings")

	agentCmd.AddCommand(agentEnrollCmd, agentPushCmd, agentStatusCmd)
	rootCmd.AddCommand(agentCmd)
}
