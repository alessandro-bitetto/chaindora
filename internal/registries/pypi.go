package registries

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PyPI is a Probe backed by pypi.org/pypi/<name>/json. PyPI doesn't
// expose a public downloads endpoint comparable to npm's api.npmjs.org;
// for that we fall back to BigQuery's pypistats.org JSON proxy. When
// pypistats isn't reachable, DownloadsLast7d returns -1 (unknown).
type PyPI struct {
	Client      *http.Client
	BaseURL     string // default: https://pypi.org/pypi
	StatsURL    string // default: https://pypistats.org/api/packages
	UserAgent   string
}

func NewPyPI() *PyPI {
	return &PyPI{
		Client:    &http.Client{Timeout: 10 * time.Second},
		BaseURL:   "https://pypi.org/pypi",
		StatsURL:  "https://pypistats.org/api/packages",
		UserAgent: "chdora-registry/",
	}
}

type pypiPackageDoc struct {
	Releases map[string][]struct {
		UploadTime string `json:"upload_time_iso_8601"`
	} `json:"releases"`
	Info struct {
		Name string `json:"name"`
	} `json:"info"`
}

func (p *PyPI) Exists(ctx context.Context, name string) (bool, error) {
	status, _, err := p.fetchPackage(ctx, name)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("pypi exists %s: HTTP %d", name, status)
	}
}

func (p *PyPI) PublishedAt(ctx context.Context, name string) (time.Time, error) {
	status, doc, err := p.fetchPackage(ctx, name)
	if err != nil {
		return time.Time{}, err
	}
	if status == http.StatusNotFound || doc == nil {
		return time.Time{}, nil
	}
	if status != http.StatusOK {
		return time.Time{}, fmt.Errorf("pypi publishedAt %s: HTTP %d", name, status)
	}
	// Earliest upload across all releases.
	var earliest time.Time
	for _, rel := range doc.Releases {
		for _, file := range rel {
			t, err := time.Parse(time.RFC3339Nano, file.UploadTime)
			if err != nil {
				continue
			}
			if earliest.IsZero() || t.Before(earliest) {
				earliest = t
			}
		}
	}
	return earliest, nil
}

type pypiStatsDoc struct {
	Data []struct {
		Downloads int    `json:"downloads"`
		Date      string `json:"date"`
	} `json:"data"`
}

func (p *PyPI) DownloadsLast7d(ctx context.Context, name string) (int, error) {
	enc := url.PathEscape(strings.ToLower(name))
	u := strings.TrimRight(p.StatsURL, "/") + "/" + enc + "/recent?period=week"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return -1, err
	}
	if p.UserAgent != "" {
		req.Header.Set("User-Agent", p.UserAgent)
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return -1, nil // pypistats unreachable; degrade silently
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, nil
	}
	if resp.StatusCode != http.StatusOK {
		return -1, nil
	}
	var body struct {
		Data struct {
			LastWeek int `json:"last_week"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return -1, nil
	}
	return body.Data.LastWeek, nil
}

func (p *PyPI) fetchPackage(ctx context.Context, name string) (int, *pypiPackageDoc, error) {
	enc := url.PathEscape(name)
	u := strings.TrimRight(p.BaseURL, "/") + "/" + enc + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, err
	}
	if p.UserAgent != "" {
		req.Header.Set("User-Agent", p.UserAgent)
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, nil
	}
	var doc pypiPackageDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&doc); err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, &doc, nil
}
