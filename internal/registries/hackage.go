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

// Hackage is the Haskell package registry. The HTTP API surface
// is modest:
//   - GET hackage.haskell.org/package/<name>.json
//     → { "<version>": "publish-date-rfc3339" } map
//   - GET hackage.haskell.org/package/<name>-<version>/uploaders
//     → text/plain: "userName"  (the uploader account)
//   - GET hackage.haskell.org/package/<name>-<version>/<name>-<version>.tar.gz
//     → the source archive
//
// No per-package "owners" abstraction beyond uploaders; we use the
// uploader as the publisher signal.
type Hackage struct {
	Client    *http.Client
	BaseURL   string // default: https://hackage.haskell.org
	UserAgent string
}

func NewHackage() *Hackage {
	return &Hackage{
		Client:    &http.Client{Timeout: 10 * time.Second},
		BaseURL:   "https://hackage.haskell.org",
		UserAgent: "chdora-registry/",
	}
}

type hackageVersionList map[string]string

func (h *Hackage) fetchVersions(ctx context.Context, name string) (hackageVersionList, error) {
	u := strings.TrimRight(h.BaseURL, "/") + "/package/" + url.PathEscape(name) + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if h.UserAgent != "" {
		req.Header.Set("User-Agent", h.UserAgent)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hackage %s: HTTP %d", name, resp.StatusCode)
	}
	var doc hackageVersionList
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func (h *Hackage) fetchUploader(ctx context.Context, name, version string) (string, error) {
	u := strings.TrimRight(h.BaseURL, "/") + "/package/" + url.PathEscape(name+"-"+version) + "/uploaders"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	if h.UserAgent != "" {
		req.Header.Set("User-Agent", h.UserAgent)
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := h.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (h *Hackage) PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error) {
	vs, err := h.fetchVersions(ctx, name)
	if err != nil || vs == nil {
		return time.Time{}, err
	}
	if d, ok := vs[version]; ok {
		t, _ := time.Parse(time.RFC3339, d)
		return t, nil
	}
	return time.Time{}, nil
}

func (h *Hackage) PublisherOfVersion(ctx context.Context, name, version string) (string, error) {
	return h.fetchUploader(ctx, name, version)
}

func (h *Hackage) AllVersions(ctx context.Context, name string) ([]VersionInfo, error) {
	vs, err := h.fetchVersions(ctx, name)
	if err != nil || vs == nil {
		return nil, err
	}
	out := make([]VersionInfo, 0, len(vs))
	for v, d := range vs {
		t, _ := time.Parse(time.RFC3339, d)
		out = append(out, VersionInfo{
			Name:        name,
			Version:     v,
			PublishedAt: t,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublishedAt.Before(out[j].PublishedAt) })
	return out, nil
}

func (h *Hackage) TarballURL(ctx context.Context, name, version string) (string, error) {
	nv := name + "-" + version
	return fmt.Sprintf("%s/package/%s/%s.tar.gz",
		strings.TrimRight(h.BaseURL, "/"),
		url.PathEscape(nv),
		url.PathEscape(nv)), nil
}

func (h *Hackage) FetchTarball(ctx context.Context, fetchURL string, dst io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return err
	}
	if h.UserAgent != "" {
		req.Header.Set("User-Agent", h.UserAgent)
	}
	resp, err := h.Client.Do(req)
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
