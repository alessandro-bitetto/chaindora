package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// TestEndToEnd_EnrollPushList walks the canonical happy path:
// agent enrolls → pushes a scan → server returns it via list +
// summary endpoints.
func TestEndToEnd_EnrollPushList(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := New(store, "shared-secret", "test")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Enroll without secret → forbidden.
	resp, err := http.Post(ts.URL+"/api/v1/agents/enroll", "application/json",
		strings.NewReader(`{"name":"alice"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("enroll without secret: got %d, want 403", resp.StatusCode)
	}

	// Enroll with correct secret.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/agents/enroll",
		strings.NewReader(`{"name":"alice","hostname":"laptop"}`))
	req.Header.Set("X-Chaindora-Enroll-Secret", "shared-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("enroll: got %d: %s", resp.StatusCode, body)
	}
	var enrollResp struct {
		AgentID string `json:"agent_id"`
		APIKey  string `json:"api_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		t.Fatal(err)
	}
	if enrollResp.AgentID == "" || enrollResp.APIKey == "" {
		t.Fatalf("missing fields: %+v", enrollResp)
	}

	// Push findings without auth → 401.
	pushBody := map[string]any{
		"command":        "chdora audit",
		"chdora_version": "test",
		"findings": []findings.Finding{
			{VulnID: "CVE-1", Name: "lodash", Version: "4.17.20", Severity: findings.SeverityHigh, Detector: "osv-ioc"},
		},
	}
	pushBytes, _ := json.Marshal(pushBody)
	resp, err = http.Post(ts.URL+"/api/v1/agents/"+enrollResp.AgentID+"/scan",
		"application/json", bytes.NewReader(pushBytes))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("push without token: got %d, want 401", resp.StatusCode)
	}

	// Push with bearer token.
	req, _ = http.NewRequest(http.MethodPost,
		ts.URL+"/api/v1/agents/"+enrollResp.AgentID+"/scan",
		bytes.NewReader(pushBytes))
	req.Header.Set("Authorization", "Bearer "+enrollResp.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("push: got %d: %s", resp.StatusCode, body)
	}

	// List agents → 1.
	resp, err = http.Get(ts.URL + "/api/v1/agents")
	if err != nil {
		t.Fatal(err)
	}
	var agents []Agent
	if err := json.NewDecoder(resp.Body).Decode(&agents); err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 || agents[0].Name != "alice" {
		t.Errorf("agents: %+v", agents)
	}

	// Query findings → 1.
	resp, err = http.Get(ts.URL + "/api/v1/findings?latest=1")
	if err != nil {
		t.Fatal(err)
	}
	var records []FindingRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Finding.VulnID != "CVE-1" {
		t.Errorf("findings: %+v", records)
	}

	// Summary.
	resp, err = http.Get(ts.URL + "/api/v1/summary")
	if err != nil {
		t.Fatal(err)
	}
	var summary FleetSummary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if summary.AgentCount != 1 {
		t.Errorf("summary.AgentCount: %d, want 1", summary.AgentCount)
	}
	if summary.BySeverity["HIGH"] != 1 {
		t.Errorf("summary.BySeverity[HIGH]: %+v", summary.BySeverity)
	}

	// Dashboard at "/".
	resp, err = http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "chaindora") || !strings.Contains(string(body), "/api/v1/summary") {
		t.Errorf("dashboard missing expected content")
	}
}

func TestStore_AuthRejectsWrongToken(t *testing.T) {
	store, _ := NewStore(filepath.Join(t.TempDir(), "state.json"))
	agent, token, err := store.EnrollAgent("a", "h", "v", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateAgent(agent.ID, token); err != nil {
		t.Errorf("correct token should auth: %v", err)
	}
	if _, err := store.AuthenticateAgent(agent.ID, "wrong"); err == nil {
		t.Errorf("wrong token should reject")
	}
}

func TestStore_PersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s1, _ := NewStore(path)
	agent, _, _ := s1.EnrollAgent("a", "h", "v", "", "")
	_, _ = s1.IngestFindings(agent.ID, "cmd", "v", []findings.Finding{
		{VulnID: "X", Severity: findings.SeverityCritical},
	})
	s1.Flush()

	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.state.Agents) != 1 || len(s2.state.Findings) != 1 {
		t.Errorf("state didn't survive reopen: agents=%d findings=%d",
			len(s2.state.Agents), len(s2.state.Findings))
	}
}
