package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Cache is the disk-backed verdict store at ~/.chaindora/gate-cache/.
//
// Each cached verdict is keyed on (ecosystem, name, version,
// integrity). The integrity field is the crucial part of the key —
// without it the cache would silently approve a republished
// (compromised) version under the same name@version. With it, a
// hash collision under the same name@version becomes its own
// finding: republish-guard fires before any other checker runs.
//
// Layout on disk:
//
//	~/.chaindora/gate-cache/<ecosystem>/<sha256-of-tuple>.json
//
// One file per cached entry. Filenames hash the full key so weird
// chars in integrity strings can't escape the path; the original
// tuple is duplicated inside the file body for inspection and
// republish-guard comparisons.
//
// Cache writes happen only when:
//   - Integrity is non-empty (otherwise we can't detect tampering —
//     caching without that guard erodes the security story).
//   - The aggregated decision is Approve (Warn/Block re-evaluate
//     every time so users chasing a fix see fresh signal).
type Cache struct {
	Root string
	TTL  time.Duration
}

// CacheEntry is one cached verdict's on-disk representation.
type CacheEntry struct {
	Ecosystem string        `json:"ecosystem"`
	Name      string        `json:"name"`
	Version   string        `json:"version"`
	Integrity string        `json:"integrity"`
	CachedAt  time.Time     `json:"cached_at"`
	Results   []CheckResult `json:"results"`
}

// CacheStat is a per-ecosystem rollup for `chdora gate cache stats`.
type CacheStat struct {
	Ecosystem string
	Entries   int
}

// NewCache returns a Cache rooted at the given path with the given
// approve-verdict TTL.
func NewCache(root string, ttl time.Duration) *Cache {
	return &Cache{Root: root, TTL: ttl}
}

// DefaultCacheRoot returns ~/.chaindora/gate-cache. Empty string on
// home-dir lookup failure — callers should treat that as "caching
// disabled" rather than fatal.
func DefaultCacheRoot() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".chaindora", "gate-cache")
}

// keyHash hashes the full tuple so the filename is safe regardless
// of integrity-string contents (sha512-... can include '+' and '/'
// from base64).
func cacheKeyHash(ref PackageRef) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s", ref.Ecosystem, ref.Name, ref.Version, ref.Integrity)
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func (c *Cache) entryPath(ref PackageRef) string {
	return filepath.Join(c.Root, ref.Ecosystem, cacheKeyHash(ref)+".json")
}

// Lookup returns the cached entry exactly matching ref's full key,
// or nil on any miss / unreadable / expired entry. Never returns an
// error — a cache miss must be silent so caching stays a pure perf
// addition, never a correctness blocker.
func (c *Cache) Lookup(ref PackageRef) *CacheEntry {
	if c == nil || c.Root == "" || ref.Integrity == "" {
		return nil
	}
	data, err := os.ReadFile(c.entryPath(ref))
	if err != nil {
		return nil
	}
	var e CacheEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil
	}
	if c.TTL > 0 && time.Since(e.CachedAt) > c.TTL {
		return nil
	}
	return &e
}

// LookupAnyIntegrity walks the ecosystem's cache directory looking
// for a previously-cached entry with the same (eco, name, version)
// — regardless of integrity. This is what powers republish
// detection: if we cached lodash@4.17.21 with integrity X, and
// today's install presents integrity Y, that's a smoking gun for
// "the upstream tarball was overwritten with different bytes."
//
// O(directory size). Acceptable cost: each ecosystem directory has
// at most a few hundred unique versions, and this only runs when
// the exact-match Lookup missed.
func (c *Cache) LookupAnyIntegrity(eco, name, version string) *CacheEntry {
	if c == nil || c.Root == "" {
		return nil
	}
	dir := filepath.Join(c.Root, eco)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var entry CacheEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		if entry.Name != name || entry.Version != version {
			continue
		}
		if c.TTL > 0 && time.Since(entry.CachedAt) > c.TTL {
			continue
		}
		return &entry
	}
	return nil
}

// Store writes a verdict to disk. Silently skips when integrity is
// empty (no tamper signal possible) or the decision isn't Approve
// (Warn/Block deserve fresh evaluation each run). Returns errors so
// caller can log them, but callers should treat write failures as
// non-fatal — caching is pure perf addition.
func (c *Cache) Store(ref PackageRef, pc PackageCheck) error {
	if c == nil || c.Root == "" || ref.Integrity == "" {
		return nil
	}
	if pc.Decision() != VerdictApprove {
		return nil
	}
	entry := CacheEntry{
		Ecosystem: ref.Ecosystem,
		Name:      ref.Name,
		Version:   ref.Version,
		Integrity: ref.Integrity,
		CachedAt:  time.Now().UTC(),
		Results:   pc.Results,
	}
	p := c.entryPath(ref)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Clear removes the entire cache root. Safe to call when the cache
// doesn't exist yet — returns nil in that case.
func (c *Cache) Clear() error {
	if c == nil || c.Root == "" {
		return nil
	}
	if err := os.RemoveAll(c.Root); err != nil {
		return err
	}
	return nil
}

// Stats walks the cache root and counts entries per ecosystem.
// Returns nil, nil if the cache directory doesn't exist yet
// (treated as empty).
func (c *Cache) Stats() ([]CacheStat, error) {
	if c == nil || c.Root == "" {
		return nil, nil
	}
	ents, err := os.ReadDir(c.Root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var stats []CacheStat
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		sub, err := os.ReadDir(filepath.Join(c.Root, e.Name()))
		if err != nil {
			continue
		}
		n := 0
		for _, s := range sub {
			if !s.IsDir() && strings.HasSuffix(s.Name(), ".json") {
				n++
			}
		}
		stats = append(stats, CacheStat{Ecosystem: e.Name(), Entries: n})
	}
	return stats, nil
}
