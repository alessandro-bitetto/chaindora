package registries

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// CPAN is the Perl module archive, indexed by MetaCPAN. The API:
//   - POST fastapi.metacpan.org/v1/release/_search
//     ES-style query: { "query": { "term": { "distribution": "<dist>" } } }
//     returns every release of a distribution.
//   - GET fastapi.metacpan.org/v1/release/<author>/<release-name>
//     per-release detail.
//
// In CPAN, "module" (Foo::Bar) and "distribution" (Foo-Bar) are
// different. Lockfile entries (cpanfile.snapshot, Carton, carmel)
// record distributions. Tarballs live on the metacpan CDN at
// /v1/source/<author>/<release>/<path>.tar.gz (or .meta blob).
//
// CPAN's per-release "author" field is a PAUSE author ID
// (uppercase, e.g. "GAAS", "SHAY"). We use that directly as the
// publisher key — it's account-bound and stable.
type CPAN struct {
	Client    *http.Client
	BaseURL   string // default: https://fastapi.metacpan.org/v1
	UserAgent string
}

func NewCPAN() *CPAN {
	return &CPAN{
		Client:    &http.Client{Timeout: 10 * time.Second},
		BaseURL:   "https://fastapi.metacpan.org/v1",
		UserAgent: "chdora-registry/",
	}
}

type cpanHits struct {
	Hits struct {
		Hits []cpanHit `json:"hits"`
	} `json:"hits"`
}

type cpanHit struct {
	Source cpanRelease `json:"_source"`
}

type cpanRelease struct {
	Distribution string `json:"distribution"`
	Version      string `json:"version"`
	Date         string `json:"date"`
	Author       string `json:"author"`
	Name         string `json:"name"`
	Download     string `json:"download_url"`
}

// fetchReleases pulls every release of a distribution via the
// _search endpoint. CPAN's API caps `size` at 500; for packages
// with more history the older entries are dropped, which is fine
// for gate-time signal-shaping (cooldown / publisher-change need
// recent history, not deep archaeology).
func (c *CPAN) fetchReleases(ctx context.Context, distribution string) ([]cpanRelease, error) {
	body := map[string]interface{}{
		"size": 500,
		"sort": []map[string]string{{"date": "desc"}},
		"query": map[string]interface{}{
			"term": map[string]string{
				"distribution": distribution,
			},
		},
		"_source": []string{"distribution", "version", "date", "author", "name", "download_url"},
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	u := strings.TrimRight(c.BaseURL, "/") + "/release/_search"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cpan %s: HTTP %d", distribution, resp.StatusCode)
	}
	var doc cpanHits
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	out := make([]cpanRelease, 0, len(doc.Hits.Hits))
	for _, h := range doc.Hits.Hits {
		out = append(out, h.Source)
	}
	sort.Slice(out, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339, out[i].Date)
		tj, _ := time.Parse(time.RFC3339, out[j].Date)
		return ti.Before(tj)
	})
	return out, nil
}

func (c *CPAN) PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error) {
	rels, err := c.fetchReleases(ctx, name)
	if err != nil {
		return time.Time{}, err
	}
	for _, r := range rels {
		if r.Version == version {
			t, _ := time.Parse(time.RFC3339, r.Date)
			return t, nil
		}
	}
	return time.Time{}, nil
}

func (c *CPAN) PublisherOfVersion(ctx context.Context, name, version string) (string, error) {
	rels, err := c.fetchReleases(ctx, name)
	if err != nil {
		return "", err
	}
	for _, r := range rels {
		if r.Version == version {
			return r.Author, nil
		}
	}
	return "", nil
}

func (c *CPAN) AllVersions(ctx context.Context, name string) ([]VersionInfo, error) {
	rels, err := c.fetchReleases(ctx, name)
	if err != nil {
		return nil, err
	}
	out := make([]VersionInfo, 0, len(rels))
	for _, r := range rels {
		t, _ := time.Parse(time.RFC3339, r.Date)
		out = append(out, VersionInfo{
			Name:        name,
			Version:     r.Version,
			Publisher:   r.Author,
			PublishedAt: t,
		})
	}
	return out, nil
}

func (c *CPAN) TarballURL(ctx context.Context, name, version string) (string, error) {
	rels, err := c.fetchReleases(ctx, name)
	if err != nil {
		return "", err
	}
	for _, r := range rels {
		if r.Version == version && r.Download != "" {
			return r.Download, nil
		}
	}
	return "", nil
}

func (c *CPAN) FetchTarball(ctx context.Context, fetchURL string, dst io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.Client.Do(req)
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
