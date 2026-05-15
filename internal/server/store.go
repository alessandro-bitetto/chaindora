// Package server is the v0.13 multi-machine fleet store. A single
// chdora-server process accepts findings from multiple agents,
// persists them, and serves a fleet-wide view.
//
// Storage is a single JSON file at <data-dir>/state.json. SQLite
// would be the right tool for arbitrary queries, but the use case
// here is modest (typically tens-to-hundreds of agents, low write
// volume) and an in-memory + atomic-JSON-flush model avoids the
// Cgo / cross-compile pain that comes with sqlite drivers.
//
// State persistence:
//   - Load on startup.
//   - Flush on every mutating call (Save() is cheap relative to
//     network I/O; we'd rather pay it than risk loss on crash).
//   - Atomic write (temp + rename) so a partial write can't corrupt
//     an existing state file.
package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// Agent is one enrolled machine. APIKeyHash is the SHA-256 of the
// bearer token issued at enrollment time; the raw token is shown
// once to the caller and never persisted.
type Agent struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Hostname   string    `json:"hostname,omitempty"`
	APIKeyHash string    `json:"api_key_hash"`
	EnrolledAt time.Time `json:"enrolled_at"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
	ChdoraVer  string    `json:"chdora_version,omitempty"`
}

// Scan is one delivery of findings from an agent.
type Scan struct {
	ID            string    `json:"id"`
	AgentID       string    `json:"agent_id"`
	ReceivedAt    time.Time `json:"received_at"`
	Command       string    `json:"command,omitempty"`
	ChdoraVer     string    `json:"chdora_version,omitempty"`
	FindingCount  int       `json:"finding_count"`
}

// FindingRecord pairs a Finding with its delivery context.
type FindingRecord struct {
	AgentID     string           `json:"agent_id"`
	ScanID      string           `json:"scan_id"`
	ReceivedAt  time.Time        `json:"received_at"`
	Fingerprint string           `json:"fingerprint"`
	Finding     findings.Finding `json:"finding"`
}

// State is the on-disk shape. Versioned so we can migrate later.
type State struct {
	Schema   int                       `json:"schema"`
	Agents   map[string]Agent          `json:"agents"`
	Scans    []Scan                    `json:"scans"`
	Findings []FindingRecord           `json:"findings"`
}

// Store is the mutex-protected wrapper around State.
type Store struct {
	mu    sync.RWMutex
	path  string
	state State
}

// NewStore opens (or initializes) the store at path. Returns an
// error only on read / parse failure of an existing file; a
// missing file yields a fresh empty store.
func NewStore(path string) (*Store, error) {
	s := &Store{
		path:  path,
		state: State{Schema: 1, Agents: map[string]Agent{}},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("server store: read %s: %w", s.path, err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("server store: parse %s: %w", s.path, err)
	}
	if st.Agents == nil {
		st.Agents = map[string]Agent{}
	}
	s.state = st
	return nil
}

// save flushes state to disk atomically. Holds the read lock —
// callers must take the write lock externally if they're mutating.
func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, s.path)
}

// Flush forces a state write. The HTTP server calls this on
// shutdown to make sure nothing in-flight is lost.
func (s *Store) Flush() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.save()
}

// EnrollAgent registers a new agent and returns the raw bearer
// token. The token is shown ONCE — agents must persist it; the
// server only stores its hash.
//
// enrollmentSecret is an optional pre-shared secret that gates
// who can enroll. Empty means "enrollment is open" — appropriate
// for trusted internal networks; production deployments should
// always set it. Token rotation isn't implemented in v0.13.0
// (delete-and-re-enroll is the workflow).
func (s *Store) EnrollAgent(name, hostname, chdoraVer, enrollmentSecret, providedSecret string) (agent Agent, rawToken string, err error) {
	if enrollmentSecret != "" && providedSecret != enrollmentSecret {
		return Agent{}, "", errors.New("enrollment secret mismatch")
	}
	if strings.TrimSpace(name) == "" {
		return Agent{}, "", errors.New("agent name is required")
	}
	rawToken, err = newToken()
	if err != nil {
		return Agent{}, "", err
	}
	agent = Agent{
		ID:         newID(),
		Name:       name,
		Hostname:   hostname,
		APIKeyHash: hashToken(rawToken),
		EnrolledAt: time.Now().UTC(),
		ChdoraVer:  chdoraVer,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Agents[agent.ID] = agent
	if err := s.save(); err != nil {
		return Agent{}, "", err
	}
	return agent, rawToken, nil
}

// AuthenticateAgent looks up an agent by ID and verifies the
// supplied bearer token. Returns the agent on success or an
// error suitable for HTTP 401 responses.
func (s *Store) AuthenticateAgent(agentID, rawToken string) (Agent, error) {
	s.mu.RLock()
	a, ok := s.state.Agents[agentID]
	s.mu.RUnlock()
	if !ok {
		return Agent{}, errors.New("unknown agent")
	}
	if a.APIKeyHash != hashToken(rawToken) {
		return Agent{}, errors.New("invalid api key")
	}
	return a, nil
}

// IngestFindings stores a new scan + every finding it carried.
// Updates the agent's LastSeen + ChdoraVer.
func (s *Store) IngestFindings(agentID, command, chdoraVer string, fs []findings.Finding) (Scan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.state.Agents[agentID]
	if !ok {
		return Scan{}, errors.New("unknown agent")
	}
	scan := Scan{
		ID:           newID(),
		AgentID:      agentID,
		ReceivedAt:   time.Now().UTC(),
		Command:      command,
		ChdoraVer:    chdoraVer,
		FindingCount: len(fs),
	}
	s.state.Scans = append(s.state.Scans, scan)
	for _, f := range fs {
		s.state.Findings = append(s.state.Findings, FindingRecord{
			AgentID:     agentID,
			ScanID:      scan.ID,
			ReceivedAt:  scan.ReceivedAt,
			Fingerprint: findings.Fingerprint(f),
			Finding:     f,
		})
	}
	a.LastSeen = scan.ReceivedAt
	if chdoraVer != "" {
		a.ChdoraVer = chdoraVer
	}
	s.state.Agents[agentID] = a
	if err := s.save(); err != nil {
		return Scan{}, err
	}
	return scan, nil
}

// FindingFilter narrows the result set for QueryFindings.
type FindingFilter struct {
	AgentID    string
	Severity   findings.Severity
	Since      time.Time
	Limit      int
	OnlyLatest bool // include only the most recent occurrence per fingerprint
}

// QueryFindings returns findings matching f. Results are sorted
// newest-first by ReceivedAt. Limit defaults to 1000 when zero.
func (s *Store) QueryFindings(f FindingFilter) []FindingRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]FindingRecord, 0, 64)
	seen := map[string]struct{}{}
	// Reverse iterate so most-recent-first dedupe wins.
	for i := len(s.state.Findings) - 1; i >= 0; i-- {
		r := s.state.Findings[i]
		if f.AgentID != "" && r.AgentID != f.AgentID {
			continue
		}
		if f.Severity != "" && r.Finding.Severity != f.Severity {
			continue
		}
		if !f.Since.IsZero() && r.ReceivedAt.Before(f.Since) {
			continue
		}
		if f.OnlyLatest {
			if _, dup := seen[r.Fingerprint]; dup {
				continue
			}
			seen[r.Fingerprint] = struct{}{}
		}
		out = append(out, r)
		limit := f.Limit
		if limit == 0 {
			limit = 1000
		}
		if len(out) >= limit {
			break
		}
	}
	return out
}

// ListAgents returns a stable, sorted list of all enrolled agents.
func (s *Store) ListAgents() []Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Agent, 0, len(s.state.Agents))
	for _, a := range s.state.Agents {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].EnrolledAt.Before(out[j].EnrolledAt)
	})
	return out
}

// DeleteAgent removes an agent and all its findings. Returns
// false if the agent didn't exist.
func (s *Store) DeleteAgent(agentID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Agents[agentID]; !ok {
		return false, nil
	}
	delete(s.state.Agents, agentID)
	keptScans := s.state.Scans[:0]
	for _, sc := range s.state.Scans {
		if sc.AgentID != agentID {
			keptScans = append(keptScans, sc)
		}
	}
	s.state.Scans = keptScans
	keptFindings := s.state.Findings[:0]
	for _, fr := range s.state.Findings {
		if fr.AgentID != agentID {
			keptFindings = append(keptFindings, fr)
		}
	}
	s.state.Findings = keptFindings
	return true, s.save()
}

// FleetSummary aggregates per-agent stats for the dashboard.
type FleetSummary struct {
	AgentCount   int                   `json:"agent_count"`
	FindingCount int                   `json:"finding_count"`
	BySeverity   map[string]int        `json:"by_severity"`
	ByAgent      []AgentSummary        `json:"by_agent"`
}

type AgentSummary struct {
	Agent       Agent          `json:"agent"`
	BySeverity  map[string]int `json:"by_severity"`
	Total       int            `json:"total"`
	LatestScan  time.Time      `json:"latest_scan,omitempty"`
}

// Summary builds the FleetSummary across all agents + findings.
func (s *Store) Summary() FleetSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sum := FleetSummary{
		AgentCount:   len(s.state.Agents),
		FindingCount: len(s.state.Findings),
		BySeverity:   map[string]int{},
	}
	// Use OnlyLatest semantics for the dashboard — duplicates
	// across re-scans inflate counts misleadingly.
	seen := map[string]struct{}{}
	perAgent := map[string]*AgentSummary{}
	for i := len(s.state.Findings) - 1; i >= 0; i-- {
		r := s.state.Findings[i]
		key := r.AgentID + ":" + r.Fingerprint
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		sev := string(r.Finding.Severity)
		if sev == "" {
			sev = "UNKNOWN"
		}
		sum.BySeverity[sev]++
		a := perAgent[r.AgentID]
		if a == nil {
			ag := s.state.Agents[r.AgentID]
			a = &AgentSummary{Agent: ag, BySeverity: map[string]int{}}
			perAgent[r.AgentID] = a
		}
		a.BySeverity[sev]++
		a.Total++
		if r.ReceivedAt.After(a.LatestScan) {
			a.LatestScan = r.ReceivedAt
		}
	}
	// Include zero-finding agents too — those are good news.
	for id, a := range s.state.Agents {
		if _, ok := perAgent[id]; !ok {
			perAgent[id] = &AgentSummary{Agent: a, BySeverity: map[string]int{}}
		}
	}
	for _, a := range perAgent {
		sum.ByAgent = append(sum.ByAgent, *a)
	}
	sort.Slice(sum.ByAgent, func(i, j int) bool {
		return sum.ByAgent[i].Agent.Name < sum.ByAgent[j].Agent.Name
	})
	return sum
}

// hashToken sha256s the raw bearer token. Stored on disk to
// avoid plaintext credential leaks if the state file is ever
// shared (cf. /etc/shadow).
func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// newToken generates a fresh 32-byte url-safe random token.
func newToken() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// newID is a short identifier for agents and scans.
func newID() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}
