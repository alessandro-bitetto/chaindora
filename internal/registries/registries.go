// Package registries probes upstream package registries (npm, PyPI) to
// gather evidence for behavioral heuristics. The whole point: turn
// chdora's heuristics from shape-matchers ("looks like X") into
// evidence-gatherers ("npm confirms X").
//
// Per-package facts we look up:
//   - Exists:           does this name exist on the public registry?
//   - PublishedAt:      when was this version (or the package) first published?
//   - DownloadsLast7d:  how many installs per week recently?
//
// Together these answer the three real "is this risky?" questions:
//   - dep-confusion → "exists publicly while my .npmrc says it should be private"
//   - typosquat     → "Levenshtein-close to a popular package AND fresh AND low-traffic"
//   - install-script → "has install hooks AND fresh AND low-traffic"
//
// Every probe goes through a disk cache (~/.chaindora/registry-cache.json)
// with a 24h TTL so repeat audits are free.
package registries

import (
	"context"
	"sort"
	"time"
)

// Probe is the cross-ecosystem interface every heuristic uses. Each
// ecosystem (npm, PyPI, ...) implements it with its own registry HTTP
// shape. All methods are safe to call concurrently; the underlying
// HTTP client batches and caches transparently.
type Probe interface {
	// Exists reports whether name resolves to an actual package on the
	// upstream registry. Returns nil error + false for a confirmed
	// non-existence (HTTP 404); non-nil error for transport / parse
	// failures so callers can degrade gracefully.
	Exists(ctx context.Context, name string) (bool, error)

	// PublishedAt returns when the package's first version was published.
	// Zero time + nil error means "package exists but we couldn't
	// determine the date" (legitimate edge case for some old packages).
	PublishedAt(ctx context.Context, name string) (time.Time, error)

	// DownloadsLast7d returns total install count over the last 7 days.
	// -1 means "registry doesn't expose this signal" — heuristics
	// should fall back to other evidence in that case.
	DownloadsLast7d(ctx context.Context, name string) (int, error)
}

// PackageInfo bundles the three signals so a single registry call can
// populate everything at once. Cache entries are stored in this shape.
type PackageInfo struct {
	Name             string    `json:"name"`
	Exists           bool      `json:"exists"`
	PublishedAt      time.Time `json:"published_at,omitempty"`
	DownloadsLast7d  int       `json:"downloads_last_7d,omitempty"`
	FetchedAt        time.Time `json:"fetched_at"`
}

// Fresh reports whether p was fetched within the given TTL.
func (p PackageInfo) Fresh(ttl time.Duration) bool {
	return !p.FetchedAt.IsZero() && time.Since(p.FetchedAt) < ttl
}

// VersionInfo is the per-version metadata the gate-time checks
// (cooldown, publisher-change, install-script, version-bump-diff)
// share. Cross-ecosystem: filled by NPM.VersionMetadata,
// PyPI.VersionMetadata, etc.
type VersionInfo struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Publisher   string            `json:"publisher,omitempty"`
	PublishedAt time.Time         `json:"published_at,omitempty"`
	Scripts     map[string]string `json:"scripts,omitempty"`
}

// HasInstallScript reports whether this version declares any of the
// install-time lifecycle scripts npm executes (preinstall,
// install, postinstall). PyPI's "scripts" notion is different;
// PyPI.VersionMetadata fills this field for setup.py-vs-pyproject
// equivalents.
func (v VersionInfo) HasInstallScript() bool {
	for _, k := range []string{"preinstall", "install", "postinstall"} {
		if v.Scripts[k] != "" {
			return true
		}
	}
	return false
}

// sortVersionsByPublishedAt orders versions oldest-first. Zero-time
// publish dates (legacy metadata) sort last. Used by publisher-change
// to find "the version before X."
func sortVersionsByPublishedAt(vs []VersionInfo) {
	sort.SliceStable(vs, func(i, j int) bool {
		if vs[i].PublishedAt.IsZero() != vs[j].PublishedAt.IsZero() {
			// Zero times sink to the end.
			return !vs[i].PublishedAt.IsZero()
		}
		return vs[i].PublishedAt.Before(vs[j].PublishedAt)
	})
}

// Noop returns a Probe that reports every package as nonexistent / unknown.
// Used when --skip-registry is set or no registry is configured for an
// ecosystem; heuristics see "no evidence available" and fall back to
// conservative behavior (typically: don't fire).
type Noop struct{}

func (Noop) Exists(context.Context, string) (bool, error)            { return false, nil }
func (Noop) PublishedAt(context.Context, string) (time.Time, error)  { return time.Time{}, nil }
func (Noop) DownloadsLast7d(context.Context, string) (int, error)    { return -1, nil }
