package findings

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Suppression is one entry in a project's .chaindora-ignore.yml.
// Matches can be precise (Fingerprint) or broad (VulnID +
// optional Package + optional VersionRange). Each suppression
// carries a Reason (mandatory — silent suppression is a code-
// review failure) and an optional Expires date so a suppression
// doesn't outlive the conditions that justified it.
//
// Match priority is exact-fingerprint first, then VulnID-based.
// A finding matches if ANY suppression entry matches it.
type Suppression struct {
	// Fingerprint matches exactly one finding instance. Strongest
	// possible match — survives finding renames, ecosystem shifts,
	// PURL changes. Get it via `chdora scan --format json | jq ...`.
	Fingerprint string `yaml:"fingerprint,omitempty"`

	// VulnID matches every finding with this advisory ID
	// (GHSA-*, CVE-*, MAL-*, HEUR-*, the incident-pack's own IDs).
	// Optional Package narrows by name; optional Version narrows
	// by exact version string. A bare VulnID suppresses across
	// the entire repo, which is rarely what you want — usually
	// you scope to (VulnID, Package) at minimum.
	VulnID  string `yaml:"vuln_id,omitempty"`
	Package string `yaml:"package,omitempty"`
	Version string `yaml:"version,omitempty"`

	// Reason is mandatory. The whole point of the suppression
	// file vs. /dev/null is that a future reviewer can answer
	// "why are we ignoring this?". Empty reason → parse error.
	Reason string `yaml:"reason"`

	// Expires is optional. After this date the suppression
	// CONTINUES TO APPLY (so it doesn't surprise CI overnight)
	// but the loader emits a Warn — and the renderer surfaces
	// "expired suppression" as its own line in --format=text /
	// pr-comment so it gets seen.
	Expires string `yaml:"expires,omitempty"`
}

// Suppressions is the top-level shape of .chaindora-ignore.yml.
type Suppressions struct {
	Suppress []Suppression `yaml:"suppress"`

	// Path is the file we loaded from (set by LoadSuppressions).
	// Surfaced in expired-suppression warnings so the user knows
	// where to fix.
	Path string `yaml:"-"`
}

// LoadSuppressions reads the suppression file. Returns nil + nil
// when no file is found — that's the default "no suppressions"
// state, not an error. Errors only for malformed YAML or for
// entries missing a Reason.
func LoadSuppressions(startDir string) (*Suppressions, error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", startDir, err)
	}
	for {
		for _, name := range []string{".chaindora-ignore.yml", ".chaindora-ignore.yaml", "chaindora-ignore.yml"} {
			candidate := filepath.Join(dir, name)
			info, err := os.Stat(candidate)
			if err == nil && !info.IsDir() {
				return readSuppressions(candidate)
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("stat %s: %w", candidate, err)
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, nil
		}
		dir = parent
	}
}

func readSuppressions(path string) (*Suppressions, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var s Suppressions
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	s.Path = path
	// Validate every entry has a reason. Silent suppression is
	// the failure mode this file exists to prevent.
	for i, entry := range s.Suppress {
		if strings.TrimSpace(entry.Reason) == "" {
			return nil, fmt.Errorf("%s: suppress[%d]: reason is mandatory", path, i)
		}
		if entry.Fingerprint == "" && entry.VulnID == "" {
			return nil, fmt.Errorf("%s: suppress[%d]: must set fingerprint or vuln_id", path, i)
		}
	}
	return &s, nil
}

// Matches reports whether this suppression entry matches a
// finding. Returns true if any field that's set matches; the
// fields work as AND not OR (Fingerprint OR (VulnID AND Package
// AND Version)).
func (s Suppression) Matches(f Finding) bool {
	if s.Fingerprint != "" {
		return s.Fingerprint == Fingerprint(f)
	}
	if s.VulnID != "" && s.VulnID != f.VulnID {
		return false
	}
	if s.Package != "" && s.Package != f.Name {
		return false
	}
	if s.Version != "" && s.Version != f.Version {
		return false
	}
	return s.VulnID != "" || s.Package != "" || s.Version != ""
}

// Expired reports whether the suppression's Expires date is in
// the past relative to now. False if Expires is empty or
// unparseable (we don't want a malformed date to cause silent
// expiration; the loader's stricter pass would have rejected it).
func (s Suppression) Expired(now time.Time) bool {
	if s.Expires == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", s.Expires)
	if err != nil {
		return false
	}
	return now.After(t)
}

// FilterSuppressed splits a findings list into (kept, suppressed).
// Order within each slice mirrors the input order so deterministic
// output is preserved. `now` is injectable for tests; pass
// time.Now() in production.
func FilterSuppressed(fs []Finding, supp *Suppressions, now time.Time) (kept []Finding, suppressed []SuppressedFinding) {
	if supp == nil || len(supp.Suppress) == 0 {
		return fs, nil
	}
	for _, f := range fs {
		matched := false
		for _, s := range supp.Suppress {
			if s.Matches(f) {
				suppressed = append(suppressed, SuppressedFinding{
					Finding:     f,
					Suppression: s,
					Expired:     s.Expired(now),
				})
				matched = true
				break
			}
		}
		if !matched {
			kept = append(kept, f)
		}
	}
	return kept, suppressed
}

// SuppressedFinding pairs a Finding with the Suppression entry
// that matched and a precomputed Expired flag. Used by the
// renderer to surface expired suppressions and by `--format json`
// to keep the audit trail explicit.
type SuppressedFinding struct {
	Finding     Finding     `json:"finding"`
	Suppression Suppression `json:"suppression"`
	Expired     bool        `json:"expired"`
}
