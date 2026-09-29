package registries

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Cached wraps any Probe in a disk-backed cache. Every Exists /
// PublishedAt / DownloadsLast7d call populates a PackageInfo on the
// first hit and serves from disk for the next TTL window (default 24h).
// The cache file is line-delimited JSON at ~/.chaindora/registry-cache.json
// keyed by (ecosystem, name) — safe to delete at any time (will be
// rebuilt on next call).
type Cached struct {
	Inner     Probe
	Ecosystem string        // namespace for the cache key (e.g. "npm", "pypi")
	TTL       time.Duration // default 24h
	Path      string        // cache file path; defaults to ~/.chaindora/registry-cache.json

	mu     sync.Mutex
	loaded bool
	cache  map[string]PackageInfo
}

// NewCached builds a Cached over inner. ecosystem distinguishes
// entries from different registries that share the cache file.
func NewCached(inner Probe, ecosystem string) *Cached {
	return &Cached{
		Inner:     inner,
		Ecosystem: ecosystem,
		TTL:       24 * time.Hour,
	}
}

func (c *Cached) key(name string) string { return c.Ecosystem + "|" + name }

func (c *Cached) load() {
	if c.loaded {
		return
	}
	c.cache = map[string]PackageInfo{}
	c.loaded = true
	path := c.Path
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return
		}
		path = filepath.Join(home, ".chaindora", "registry-cache.json")
		c.Path = path
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return // first run; cache empty
	}
	type entry struct {
		Key string      `json:"key"`
		Pkg PackageInfo `json:"pkg"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var e entry
		if err := dec.Decode(&e); err != nil {
			if err == io.EOF {
				break
			}
			// Corrupt entry — skip the rest, treat as cache miss.
			break
		}
		c.cache[e.Key] = e.Pkg
	}
}

func (c *Cached) get(name string) (PackageInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.load()
	info, ok := c.cache[c.key(name)]
	if !ok {
		return PackageInfo{}, false
	}
	if !info.Fresh(c.TTL) {
		return PackageInfo{}, false
	}
	return info, true
}

func (c *Cached) put(name string, info PackageInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.load()
	info.Name = name
	info.FetchedAt = time.Now()
	c.cache[c.key(name)] = info
	c.flush()
}

func (c *Cached) flush() {
	if c.Path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o755); err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.Path), "registry-cache-*")
	if err != nil {
		return
	}
	enc := json.NewEncoder(tmp)
	type entry struct {
		Key string      `json:"key"`
		Pkg PackageInfo `json:"pkg"`
	}
	for k, v := range c.cache {
		_ = enc.Encode(entry{Key: k, Pkg: v})
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return
	}
	_ = os.Rename(tmp.Name(), c.Path)
}

// Exists returns the cached existence flag if fresh; otherwise fetches
// (and caches alongside) the full PackageInfo from the inner Probe.
func (c *Cached) Exists(ctx context.Context, name string) (bool, error) {
	if info, ok := c.get(name); ok {
		return info.Exists, nil
	}
	exists, err := c.Inner.Exists(ctx, name)
	if err != nil {
		return false, err
	}
	info := PackageInfo{Exists: exists}
	if exists {
		// Best-effort: pull the additional fields too so a typosquat
		// check on the same name doesn't pay a second round trip.
		if t, terr := c.Inner.PublishedAt(ctx, name); terr == nil {
			info.PublishedAt = t
		}
		if d, derr := c.Inner.DownloadsLast7d(ctx, name); derr == nil {
			info.DownloadsLast7d = d
		}
	}
	c.put(name, info)
	return exists, nil
}

func (c *Cached) PublishedAt(ctx context.Context, name string) (time.Time, error) {
	if info, ok := c.get(name); ok {
		return info.PublishedAt, nil
	}
	// Trigger a full fetch via Exists, which populates the cache.
	if _, err := c.Exists(ctx, name); err != nil {
		return time.Time{}, err
	}
	if info, ok := c.get(name); ok {
		return info.PublishedAt, nil
	}
	return time.Time{}, nil
}

func (c *Cached) DownloadsLast7d(ctx context.Context, name string) (int, error) {
	if info, ok := c.get(name); ok {
		return info.DownloadsLast7d, nil
	}
	if _, err := c.Exists(ctx, name); err != nil {
		return -1, err
	}
	if info, ok := c.get(name); ok {
		return info.DownloadsLast7d, nil
	}
	return -1, nil
}

