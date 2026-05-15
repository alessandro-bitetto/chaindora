package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// Server is the HTTP listener wrapping the Store. Construct via
// New and pass to http.ListenAndServe / a custom listener.
type Server struct {
	Store            *Store
	EnrollmentSecret string // if set, /agents/enroll requires X-Chaindora-Enroll-Secret to match
	ChdoraVersion    string
}

// New returns a Server with the supplied store.
func New(store *Store, enrollmentSecret, chdoraVersion string) *Server {
	return &Server{
		Store:            store,
		EnrollmentSecret: enrollmentSecret,
		ChdoraVersion:    chdoraVersion,
	}
}

// Handler returns the http.Handler that serves both the JSON API
// and the dashboard. Mounted at root.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health probe — useful for load-balancer wiring. No auth.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// JSON API.
	mux.HandleFunc("/api/v1/version", s.handleVersion)
	mux.HandleFunc("/api/v1/agents/enroll", s.handleEnroll)
	mux.HandleFunc("/api/v1/agents", s.handleAgents)
	mux.HandleFunc("/api/v1/agents/", s.handleAgentsScoped) // /agents/:id/scan, /agents/:id
	mux.HandleFunc("/api/v1/findings", s.handleFindings)
	mux.HandleFunc("/api/v1/summary", s.handleSummary)

	// Dashboard — single HTML page that talks to the API above.
	mux.HandleFunc("/", s.handleDashboard)

	return loggingMiddleware(mux)
}

// loggingMiddleware emits a one-line access log per request so
// operators have a paper trail without configuring a separate
// access log. Format is similar to common log format but JSON-
// friendly so log shippers can parse it.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		fmt.Printf("[%s] %s %s %s -> %d (%dms)\n",
			start.Format(time.RFC3339),
			r.RemoteAddr, r.Method, r.URL.Path,
			rw.status, time.Since(start).Milliseconds(),
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"server":  "chdora",
		"version": s.ChdoraVersion,
		"schema":  "v1",
	})
}

// handleEnroll registers a new agent. Auth: X-Chaindora-Enroll-
// Secret header if EnrollmentSecret is configured.
//
// Request body: { "name": "...", "hostname": "..." }
// Response: { "agent_id": "...", "api_key": "raw-token" }
//
// The raw api_key is shown ONCE; the server only stores its
// SHA-256. Agents must persist the token immediately.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Name          string `json:"name"`
		Hostname      string `json:"hostname"`
		ChdoraVersion string `json:"chdora_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	provided := r.Header.Get("X-Chaindora-Enroll-Secret")
	agent, token, err := s.Store.EnrollAgent(body.Name, body.Hostname, body.ChdoraVersion, s.EnrollmentSecret, provided)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"agent_id":     agent.ID,
		"api_key":      token,
		"enrolled_at":  agent.EnrolledAt,
		"server_note":  "Persist the api_key NOW — it will not be shown again. The server only stores its SHA-256 hash.",
	})
}

// handleAgents — GET /api/v1/agents → list. Auth: none (the
// agent list is non-sensitive; auth-protect this if your fleet
// inventory itself is sensitive).
func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.Store.ListAgents())
}

// handleAgentsScoped handles /api/v1/agents/<id> and
// /api/v1/agents/<id>/scan.
func (s *Server) handleAgentsScoped(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	agentID := parts[0]
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}
	switch {
	case sub == "scan" && r.Method == http.MethodPost:
		s.handleScanUpload(w, r, agentID)
	case sub == "" && r.Method == http.MethodGet:
		s.handleAgentGet(w, r, agentID)
	case sub == "" && r.Method == http.MethodDelete:
		s.handleAgentDelete(w, r, agentID)
	default:
		http.NotFound(w, r)
	}
}

// handleAgentGet returns one agent's metadata. Auth: none.
func (s *Server) handleAgentGet(w http.ResponseWriter, r *http.Request, agentID string) {
	for _, a := range s.Store.ListAgents() {
		if a.ID == agentID {
			writeJSON(w, http.StatusOK, a)
			return
		}
	}
	http.NotFound(w, r)
}

// handleAgentDelete drops the agent + all its findings. Auth:
// must present the agent's own bearer token. This is the
// graceful-decommission path — destruction of evidence by
// adversary is mitigated by the bearer-token requirement.
func (s *Server) handleAgentDelete(w http.ResponseWriter, r *http.Request, agentID string) {
	if !s.authAgent(w, r, agentID) {
		return
	}
	removed, err := s.Store.DeleteAgent(agentID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !removed {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleScanUpload is the agent → server findings push path.
// Auth: bearer token matching the agent ID in the URL.
//
// Request:
//
//	{
//	  "command": "chdora audit --whole-machine",
//	  "chdora_version": "0.13.0",
//	  "findings": [ ... findings.Finding ... ]
//	}
//
// Response: { "scan_id": "...", "received_at": "...", "finding_count": N }
func (s *Server) handleScanUpload(w http.ResponseWriter, r *http.Request, agentID string) {
	if !s.authAgent(w, r, agentID) {
		return
	}
	var body struct {
		Command       string             `json:"command"`
		ChdoraVersion string             `json:"chdora_version"`
		Findings      []findings.Finding `json:"findings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	scan, err := s.Store.IngestFindings(agentID, body.Command, body.ChdoraVersion, body.Findings)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"scan_id":       scan.ID,
		"received_at":   scan.ReceivedAt,
		"finding_count": scan.FindingCount,
	})
}

// handleFindings — GET /api/v1/findings?agent=...&severity=...&latest=1&limit=...
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	f := FindingFilter{
		AgentID:    q.Get("agent"),
		OnlyLatest: q.Get("latest") == "1" || q.Get("latest") == "true",
	}
	if sev := q.Get("severity"); sev != "" {
		f.Severity = findings.Severity(strings.ToUpper(sev))
	}
	if l := q.Get("limit"); l != "" {
		var n int
		_, _ = fmt.Sscanf(l, "%d", &n)
		if n > 0 {
			f.Limit = n
		}
	}
	writeJSON(w, http.StatusOK, s.Store.QueryFindings(f))
}

// handleSummary — GET /api/v1/summary → FleetSummary.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.Store.Summary())
}

// authAgent verifies the bearer-token-presents-the-claimed-agent
// invariant. Writes 401 and returns false on failure; returns
// true on success without writing anything.
func (s *Server) authAgent(w http.ResponseWriter, r *http.Request, agentID string) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "missing Authorization: Bearer <token>", http.StatusUnauthorized)
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if _, err := s.Store.AuthenticateAgent(agentID, token); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
