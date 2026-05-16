package registries

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// RubyGems probes rubygems.org/api/v1. The endpoint shape is
// designed for our use case: /versions/<name>.json returns every
// version's built_at timestamp + comma-separated authors in one
// shot. /gems/<name>/owners.json gives the project-level owner
// list (the closest thing RubyGems exposes to a per-version
// publisher concept).
//
// We use authors-of-version as the "publisher" because it's the
// most version-specific identity field. owners is project-level
// and doesn't change per release (which makes it unsuitable for
// publisher-change detection).
type RubyGems struct {
	Client     *http.Client
	APIBaseURL string // default: https://rubygems.org/api/v1
	DownloadsURL string // default: https://rubygems.org/downloads
	UserAgent  string
}

func NewRubyGems() *RubyGems {
	return &RubyGems{
		Client:       &http.Client{Timeout: 10 * time.Second},
		APIBaseURL:   "https://rubygems.org/api/v1",
		DownloadsURL: "https://rubygems.org/downloads",
		UserAgent:    "chdora-registry/",
	}
}

// rubygemsVersionDoc is the shape returned by
// /api/v1/versions/<name>.json — one entry per release.
type rubygemsVersionDoc struct {
	Number      string `json:"number"`
	BuiltAt     string `json:"built_at"`
	Authors     string `json:"authors"` // comma-separated
	Summary     string `json:"summary"`
	Yanked      bool   `json:"yanked"`
}

// fetchVersions returns the full per-version timeline. Sorts
// chronologically by built_at for caller convenience.
func (r *RubyGems) fetchVersions(ctx context.Context, name string) ([]rubygemsVersionDoc, int, error) {
	u := strings.TrimRight(r.APIBaseURL, "/") + "/versions/" + url.PathEscape(name) + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	if r.UserAgent != "" {
		req.Header.Set("User-Agent", r.UserAgent)
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("rubygems versions %s: HTTP %d", name, resp.StatusCode)
	}
	var docs []rubygemsVersionDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&docs); err != nil {
		return nil, resp.StatusCode, err
	}
	sort.Slice(docs, func(i, j int) bool {
		// Sort chronologically; rubygems API returns newest-first,
		// we want oldest-first to match other ecosystems.
		ti, _ := time.Parse(time.RFC3339Nano, docs[i].BuiltAt)
		tj, _ := time.Parse(time.RFC3339Nano, docs[j].BuiltAt)
		return ti.Before(tj)
	})
	return docs, resp.StatusCode, nil
}

func (r *RubyGems) PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error) {
	docs, status, err := r.fetchVersions(ctx, name)
	if err != nil {
		return time.Time{}, err
	}
	if status == http.StatusNotFound {
		return time.Time{}, nil
	}
	for _, d := range docs {
		if d.Number == version {
			t, err := time.Parse(time.RFC3339Nano, d.BuiltAt)
			if err != nil {
				// RubyGems also uses RFC3339 without nanos for
				// some older entries.
				t, _ = time.Parse(time.RFC3339, d.BuiltAt)
			}
			return t, nil
		}
	}
	return time.Time{}, nil
}

func (r *RubyGems) PublisherOfVersion(ctx context.Context, name, version string) (string, error) {
	docs, status, err := r.fetchVersions(ctx, name)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", nil
	}
	for _, d := range docs {
		if d.Number == version {
			return d.Authors, nil
		}
	}
	return "", nil
}

func (r *RubyGems) AllVersions(ctx context.Context, name string) ([]VersionInfo, error) {
	docs, status, err := r.fetchVersions(ctx, name)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, nil
	}
	out := make([]VersionInfo, 0, len(docs))
	for _, d := range docs {
		if d.Yanked {
			continue
		}
		t, _ := time.Parse(time.RFC3339Nano, d.BuiltAt)
		if t.IsZero() {
			t, _ = time.Parse(time.RFC3339, d.BuiltAt)
		}
		out = append(out, VersionInfo{
			Name:        name,
			Version:     d.Number,
			Publisher:   d.Authors,
			PublishedAt: t,
		})
	}
	return out, nil
}

// TarballURL builds the canonical .gem URL on the public CDN.
// The .gem format is a tarball with metadata.gz + data.tar.gz
// inside; for static-pattern scanning we want data.tar.gz, but
// passing the outer .gem to scanTarball still works (it just
// sees one nested archive entry).
func (r *RubyGems) TarballURL(_ context.Context, name, version string) (string, error) {
	return fmt.Sprintf("%s/%s-%s.gem", strings.TrimRight(r.DownloadsURL, "/"), name, version), nil
}

func (r *RubyGems) FetchTarball(ctx context.Context, fetchURL string, dst io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return err
	}
	if r.UserAgent != "" {
		req.Header.Set("User-Agent", r.UserAgent)
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tarball %s: HTTP %d", fetchURL, resp.StatusCode)
	}
	_, err = io.Copy(dst, io.LimitReader(resp.Body, 50<<20))
	return err
}

// Exists reports whether name resolves to a real gem.
func (r *RubyGems) Exists(ctx context.Context, name string) (bool, error) {
	_, status, err := r.fetchVersions(ctx, name)
	if err != nil {
		return false, err
	}
	return status == http.StatusOK, nil
}

// PublishedAt returns the package's earliest publish across versions.
// Implements the registries.Probe interface for cross-ecosystem
// heuristic use.
func (r *RubyGems) PublishedAt(ctx context.Context, name string) (time.Time, error) {
	docs, _, err := r.fetchVersions(ctx, name)
	if err != nil || len(docs) == 0 {
		return time.Time{}, err
	}
	t, _ := time.Parse(time.RFC3339Nano, docs[0].BuiltAt)
	return t, nil
}

// DownloadsLast7d isn't reliably exposed by the RubyGems public
// API at per-package weekly granularity (the gem-info endpoint
// has total downloads only). Return -1 (unknown) — heuristics
// fall back to other evidence.
func (r *RubyGems) DownloadsLast7d(context.Context, string) (int, error) { return -1, nil }

// rubygemsGemVersionDoc is the per-version metadata fetched from
// /api/v1/versions/<gem>/<version>.json — narrower than the
// list endpoint and exposes Trusted Publishing attribution
// when present.
type rubygemsGemVersionDoc struct {
	Number   string `json:"number"`
	Metadata struct {
		Attribution string `json:"attribution"`
	} `json:"metadata"`
}

// fetchGemVersion returns the per-version metadata blob.
func (r *RubyGems) fetchGemVersion(ctx context.Context, name, version string) (*rubygemsGemVersionDoc, error) {
	url := fmt.Sprintf("%s/versions/%s/%s.json",
		strings.TrimRight(r.APIBaseURL, "/"),
		url.PathEscape(name), url.PathEscape(version))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if r.UserAgent != "" {
		req.Header.Set("User-Agent", r.UserAgent)
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rubygems gem-version %s@%s: HTTP %d", name, version, resp.StatusCode)
	}
	var doc rubygemsGemVersionDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// HasProvenance: RubyGems Trusted Publishing records an
// `attribution` URL in the version's metadata when the publish
// went through OIDC-attested CI (currently GitHub Actions).
// Presence is the provenance signal here.
func (r *RubyGems) HasProvenance(ctx context.Context, name, version string) (bool, error) {
	doc, err := r.fetchGemVersion(ctx, name, version)
	if err != nil || doc == nil {
		return false, err
	}
	return doc.Metadata.Attribution != "", nil
}

// AnyVersionHasProvenance: check the most recent version for an
// attribution URL. RubyGems Trusted Publishing rolled out in
// 2023, so most older versions of even adopting gems will lack
// it — the value of the check is detecting regression
// (adopted, then dropped).
func (r *RubyGems) AnyVersionHasProvenance(ctx context.Context, name string) (bool, error) {
	docs, _, err := r.fetchVersions(ctx, name)
	if err != nil || len(docs) == 0 {
		return false, err
	}
	// docs is oldest-first → check the newest.
	latest := docs[len(docs)-1]
	return r.HasProvenance(ctx, name, latest.Number)
}
