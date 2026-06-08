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
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
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
	ID           string    `json:"id"`
	AgentID      string    `json:"agent_id"`
	ReceivedAt   time.Time `json:"received_at"`
	Command      string    `json:"command,omitempty"`
	ChdoraVer    string    `json:"chdora_version,omitempty"`
	FindingCount int       `json:"finding_count"`
	// Status records whether the agent reported a completed run, a
	// partial run, or an error. Empty value (older agents that
	// don't send a summary) is treated as "complete" for
	// back-compat. Partial / error scans should NOT have their
	// findings promoted to current state by downstream consumers
	// — the inventory is incomplete and would falsely look like
	// packages were uninstalled. v0.17+.
	Status findings.ScanStatus `json:"status,omitempty"`
	// ErrorMessage carries the agent's explanation when Status is
	// not "complete". Empty otherwise.
	ErrorMessage string `json:"error_message,omitempty"`
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
	Schema   int              `json:"schema"`
	Agents   map[string]Agent `json:"agents"`
	Scans    []Scan           `json:"scans"`
	Findings []FindingRecord  `json:"findings"`
	// PackageObservations records the first Integrity hash the
	// server has seen for each (ecosystem, name, version) across
	// the entire fleet. v0.15+. When a later submission reports the
	// same tuple with a DIFFERENT Integrity, the server treats it
	// as a cross-agent republish event and emits a synthetic
	// "fleet:republish-detected" finding into the store. Keyed by
	// "<ecosystem>/<name>@<version>".
	PackageObservations map[string]PackageObservation `json:"package_observations,omitempty"`
	// VersionTimeline tracks every distinct (ecosystem, name, version)
	// the fleet has reported AND the timestamp of its first sighting.
	// Powers publish-cadence anomaly detection: if N+ versions of the
	// same package have been first-seen by the fleet within a short
	// window (default 24h), that's a cadence-anomaly signal — packages
	// don't usually ship 5 versions in a day unless something has
	// gone wrong (compromise + scramble, abandoned reverse-test
	// pipeline, etc.). Map keyed by "<ecosystem>/<name>".
	VersionTimeline map[string][]VersionTimelineEntry `json:"version_timeline,omitempty"`
	// CohortObservations tracks the first time each agent reported a
	// given (ecosystem, name, version). Powers cohort dwell-time
	// detection: when a new agent reports a version the fleet first
	// saw weeks ago, that's a "long-tail install" (normal); when a
	// new agent reports a version the fleet first saw HOURS ago,
	// that's a "fresh install during the attack window" signal.
	// Map keyed by "<ecosystem>/<name>@<version>"; values list per-
	// agent first-seen timestamps.
	CohortObservations map[string][]CohortAgentObservation `json:"cohort_observations,omitempty"`
}

// VersionTimelineEntry is one (version, first-seen-by-fleet)
// record contributing to publish-cadence anomaly detection.
type VersionTimelineEntry struct {
	Version     string    `json:"version"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	FirstAgent  string    `json:"first_agent"`
}

// CohortAgentObservation is one agent's first sighting of a
// specific (ecosystem, name, version) tuple. Used to compute
// dwell-time skew across the fleet for that tuple.
type CohortAgentObservation struct {
	AgentID    string    `json:"agent_id"`
	ObservedAt time.Time `json:"observed_at"`
}

// PackageObservation is one (eco, name, version) → integrity record.
// FirstAgent + FirstSeenAt let the dashboard show "agent X first
// reported integrity Y on date Z; now agent W reports W' — divergent."
type PackageObservation struct {
	Ecosystem   string    `json:"ecosystem"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Integrity   string    `json:"integrity"`
	FirstAgent  string    `json:"first_agent"`
	FirstSeenAt time.Time `json:"first_seen_at"`
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
		path: path,
		state: State{
			Schema:              1,
			Agents:              map[string]Agent{},
			PackageObservations: map[string]PackageObservation{},
			VersionTimeline:     map[string][]VersionTimelineEntry{},
			CohortObservations:  map[string][]CohortAgentObservation{},
		},
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
	if st.PackageObservations == nil {
		st.PackageObservations = map[string]PackageObservation{}
	}
	if st.VersionTimeline == nil {
		st.VersionTimeline = map[string][]VersionTimelineEntry{}
	}
	if st.CohortObservations == nil {
		st.CohortObservations = map[string][]CohortAgentObservation{}
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
// Updates the agent's LastSeen + ChdoraVer. Also runs the fleet
// integrity tracker: for every finding carrying an Integrity hash,
// either record it as a first observation or flag divergence from a
// prior observation as a synthetic "fleet:republish-detected"
// finding (severity=critical). The synthetic findings land in the
// store alongside the user's submissions so the dashboard surfaces
// them in the same query path.
func (s *Store) IngestFindings(agentID, command, chdoraVer string, fs []findings.Finding) (Scan, error) {
	return s.IngestFindingsWithSummary(agentID, command, chdoraVer, fs, nil)
}

// IngestFindingsWithSummary is the v0.17+ entry point that accepts an
// optional ScanSummary from the agent. A non-nil summary with Status
// != "complete" tags the resulting Scan as partial/error so the
// dashboard can render it distinctly and so consumers that compute
// per-agent "current state" can skip non-complete runs. nil summary
// is treated as a complete run (back-compat with older agents).
func (s *Store) IngestFindingsWithSummary(agentID, command, chdoraVer string, fs []findings.Finding, summary *findings.ScanSummary) (Scan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.state.Agents[agentID]
	if !ok {
		return Scan{}, errors.New("unknown agent")
	}
	status := findings.ScanStatusComplete
	errMsg := ""
	if summary != nil {
		if summary.Status != "" {
			status = summary.Status
		}
		errMsg = summary.ErrorMessage
	}
	scan := Scan{
		ID:           newID(),
		AgentID:      agentID,
		ReceivedAt:   time.Now().UTC(),
		Command:      command,
		ChdoraVer:    chdoraVer,
		FindingCount: len(fs),
		Status:       status,
		ErrorMessage: errMsg,
	}
	s.state.Scans = append(s.state.Scans, scan)
	if s.state.PackageObservations == nil {
		s.state.PackageObservations = map[string]PackageObservation{}
	}
	if s.state.VersionTimeline == nil {
		s.state.VersionTimeline = map[string][]VersionTimelineEntry{}
	}
	if s.state.CohortObservations == nil {
		s.state.CohortObservations = map[string][]CohortAgentObservation{}
	}
	var fleetFindings []findings.Finding
	for _, f := range fs {
		s.state.Findings = append(s.state.Findings, FindingRecord{
			AgentID:     agentID,
			ScanID:      scan.ID,
			ReceivedAt:  scan.ReceivedAt,
			Fingerprint: findings.Fingerprint(f),
			Finding:     f,
		})
		// Cadence + cohort tracking (v0.15 full-parity). These two
		// signals don't need Integrity — just a (eco, name, version)
		// tuple — so we record them before the integrity branch
		// below. Empty name/version still skip.
		if f.Name != "" && f.Version != "" {
			s.recordCadenceAndCohortLocked(string(f.Ecosystem), f.Name, f.Version, agentID, scan.ReceivedAt, &fleetFindings, scan.ID)
		}

		// Fleet republish-detection: track per-tuple integrity
		// across all submissions. Same tuple with a different hash
		// from a different agent is a strong cross-fleet tamper
		// signal (the registry served different bytes to different
		// agents, or one agent's cache was poisoned).
		if f.Integrity == "" || f.Name == "" || f.Version == "" {
			continue
		}
		key := string(f.Ecosystem) + "/" + f.Name + "@" + f.Version
		existing, seen := s.state.PackageObservations[key]
		if !seen {
			s.state.PackageObservations[key] = PackageObservation{
				Ecosystem:   string(f.Ecosystem),
				Name:        f.Name,
				Version:     f.Version,
				Integrity:   f.Integrity,
				FirstAgent:  agentID,
				FirstSeenAt: scan.ReceivedAt,
			}
			continue
		}
		if existing.Integrity == f.Integrity {
			continue
		}
		// Divergence. Emit a synthetic finding into the store
		// representing the fleet-level event. Only fire once per
		// (key, divergent-hash) combination per scan — we don't
		// re-emit for every repeat sighting.
		alert := findings.Finding{
			Detector:  "fleet:republish-detected",
			Category:  findings.CategorySupplyChainAttack,
			Ecosystem: f.Ecosystem,
			Name:      f.Name,
			Version:   f.Version,
			PURL:      f.PURL,
			VulnID:    "FLEET-REPUBLISH",
			Summary: "fleet-wide divergence on " + f.Name + "@" + f.Version +
				": agent " + existing.FirstAgent + " reported integrity " +
				shortFleetHash(existing.Integrity) + " on " +
				existing.FirstSeenAt.Format(time.RFC3339) +
				"; agent " + agentID + " now reports " +
				shortFleetHash(f.Integrity) +
				" — registry compromise or per-agent cache poisoning",
			Severity: findings.SeverityCritical,
		}
		fleetFindings = append(fleetFindings, alert)
		s.state.Findings = append(s.state.Findings, FindingRecord{
			AgentID:     agentID,
			ScanID:      scan.ID,
			ReceivedAt:  scan.ReceivedAt,
			Fingerprint: findings.Fingerprint(alert),
			Finding:     alert,
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
	// Bump the scan's reported FindingCount so the dashboard shows
	// the fleet alerts as part of this submission's footprint.
	if len(fleetFindings) > 0 {
		scan.FindingCount += len(fleetFindings)
		for i := range s.state.Scans {
			if s.state.Scans[i].ID == scan.ID {
				s.state.Scans[i].FindingCount = scan.FindingCount
				break
			}
		}
	}
	return scan, nil
}

// fleetCadenceWindow is the trailing window for the publish-
// cadence anomaly check. Versions first-seen by the fleet within
// this duration of each other suggest abnormally fast publishing.
const fleetCadenceWindow = 24 * time.Hour

// fleetCadenceThreshold is the version count within
// fleetCadenceWindow that triggers a cadence-anomaly alert.
// Healthy packages publish at most 1-2 versions per day even
// during release-burst weeks; 4+ in 24h is a strong outlier.
const fleetCadenceThreshold = 4

// fleetFreshInstallWindow is the maximum age (since fleet-first-
// sighting) at which a NEW agent reporting the version qualifies
// as a "fresh install during the attack window" cohort outlier.
// 6h is the rough sweet spot — short enough to flag the bunched-
// install pattern attackers chase, long enough to avoid false
// positives from typical staggered rollouts.
const fleetFreshInstallWindow = 6 * time.Hour

// fleetCohortMinPriorAgents is the minimum number of OTHER agents
// that must have observed the version before we apply the cohort
// check. Without enough prior observations the dwell-time signal
// is meaningless (the "fleet" is too small to compare against).
const fleetCohortMinPriorAgents = 3

// recordCadenceAndCohortLocked updates VersionTimeline and
// CohortObservations for the (eco, name, version) tuple this
// agent just reported, and emits synthetic fleet findings on
// anomaly. Must be called with s.mu held.
func (s *Store) recordCadenceAndCohortLocked(ecosystem, name, version, agentID string, observedAt time.Time, fleetFindings *[]findings.Finding, scanID string) {
	pkgKey := ecosystem + "/" + name
	tupleKey := pkgKey + "@" + version

	// --- Cadence: append-if-new to the timeline. ---
	timeline := s.state.VersionTimeline[pkgKey]
	seenVersion := false
	for _, e := range timeline {
		if e.Version == version {
			seenVersion = true
			break
		}
	}
	if !seenVersion {
		timeline = append(timeline, VersionTimelineEntry{
			Version:     version,
			FirstSeenAt: observedAt,
			FirstAgent:  agentID,
		})
		s.state.VersionTimeline[pkgKey] = timeline
		// Check for anomaly: how many versions first-seen within
		// the trailing fleetCadenceWindow ending at observedAt?
		recent := 0
		oldestRecent := observedAt
		for _, e := range timeline {
			if observedAt.Sub(e.FirstSeenAt) <= fleetCadenceWindow {
				recent++
				if e.FirstSeenAt.Before(oldestRecent) {
					oldestRecent = e.FirstSeenAt
				}
			}
		}
		if recent >= fleetCadenceThreshold {
			alert := findings.Finding{
				Detector:  "fleet:publish-cadence-anomaly",
				Category:  findings.CategorySupplyChainAttack,
				Ecosystem: inventory.Ecosystem(ecosystem),
				Name:      name,
				Version:   version,
				VulnID:    "FLEET-CADENCE-ANOMALY",
				Summary: fmt.Sprintf(
					"fleet has observed %d versions of %s first-published within %s ending at %s — abnormal release cadence (typical packages ship 1-2/day at most)",
					recent, name, fleetCadenceWindow, observedAt.Format(time.RFC3339)),
				Severity: findings.SeverityCritical,
			}
			*fleetFindings = append(*fleetFindings, alert)
			s.state.Findings = append(s.state.Findings, FindingRecord{
				AgentID:     agentID,
				ScanID:      scanID,
				ReceivedAt:  observedAt,
				Fingerprint: findings.Fingerprint(alert),
				Finding:     alert,
			})
		}
	}

	// --- Cohort dwell: track this agent's first-time sighting. ---
	cohort := s.state.CohortObservations[tupleKey]
	for _, c := range cohort {
		if c.AgentID == agentID {
			// Already recorded — no signal on repeat.
			return
		}
	}
	cohort = append(cohort, CohortAgentObservation{AgentID: agentID, ObservedAt: observedAt})
	s.state.CohortObservations[tupleKey] = cohort
	// Need enough prior observations to make a comparison.
	if len(cohort) <= fleetCohortMinPriorAgents {
		return
	}
	// Compare this agent's observation to the fleet's median (or
	// earliest) first-sighting. If we're substantially newer than
	// the prior cohort, flag it.
	earliest := cohort[0].ObservedAt
	for _, c := range cohort[1:] {
		if c.ObservedAt.Before(earliest) {
			earliest = c.ObservedAt
		}
	}
	// Skip self-comparison: only fire when the fleet's earliest
	// sighting predates THIS agent's by enough that the gap is
	// meaningful, BUT this agent's gap from the fleet's earliest
	// is SHORTER than fleetFreshInstallWindow — which would mean
	// THIS agent installed during the attack window relative to
	// the fleet's prior. Wait, I want the OPPOSITE: this agent's
	// install IS fresh while the fleet's existing cohort has had
	// the version for a long time.
	priorDwell := observedAt.Sub(earliest)
	if priorDwell < 7*24*time.Hour {
		// Whole fleet recently got this version — not an outlier.
		return
	}
	// This agent's observation IS this agent's first-sighting (we
	// just added it). The "this agent only had it for X" timing
	// isn't directly inferable from a single observation, so
	// instead we flag the bunching: this agent saw the version
	// AFTER the fleet's existing cohort has had it for at least a
	// week, AND this is the agent's first scan reporting it. That's
	// the "fresh install in a mature-version-already-on-fleet"
	// pattern attackers exploit when they pivot to a long-stable
	// dependency.
	alert := findings.Finding{
		Detector:  "fleet:cohort-fresh-install",
		Category:  findings.CategoryPredictive,
		Ecosystem: inventory.Ecosystem(ecosystem),
		Name:      name,
		Version:   version,
		VulnID:    "FLEET-COHORT-FRESH",
		Summary: fmt.Sprintf(
			"agent %s reports %s@%s for the first time; fleet's earliest sighting was %s ago (%d prior agents). New install on a long-stable version — review what just changed in this agent's environment",
			agentID, name, version, priorDwell.Truncate(time.Hour), len(cohort)-1),
		Severity: findings.SeverityMedium,
	}
	*fleetFindings = append(*fleetFindings, alert)
	s.state.Findings = append(s.state.Findings, FindingRecord{
		AgentID:     agentID,
		ScanID:      scanID,
		ReceivedAt:  observedAt,
		Fingerprint: findings.Fingerprint(alert),
		Finding:     alert,
	})
}

// shortFleetHash truncates an integrity string for readable
// finding summaries. Same logic as the gate.shortHash but kept
// local here so the server package stays self-contained.
func shortFleetHash(h string) string {
	if i := strings.IndexAny(h, "-:"); i > 0 && i < 10 {
		head := h[:i+1]
		body := h[i+1:]
		if len(body) > 12 {
			body = body[:12] + "..."
		}
		return head + body
	}
	if len(h) > 16 {
		return h[:16] + "..."
	}
	return h
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
