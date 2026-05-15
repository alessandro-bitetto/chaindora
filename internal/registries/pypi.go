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
	Releases map[string][]pypiReleaseFile `json:"releases"`
	Info     struct {
		Name            string `json:"name"`
		MaintainerEmail string `json:"maintainer_email"`
		AuthorEmail     string `json:"author_email"`
		ProjectURL      string `json:"project_url"`
	} `json:"info"`
}

type pypiReleaseFile struct {
	UploadTime string `json:"upload_time_iso_8601"`
	URL        string `json:"url"`
	Filename   string `json:"filename"`
	Packagetype string `json:"packagetype"` // "sdist" or "bdist_wheel"
}

// PublishedAtVersion returns the upload timestamp for a specific
// release. PyPI's "release" can have multiple files (sdist, wheels
// per Python version) — we return the EARLIEST upload time so the
// cooldown check measures "when did this version first appear,"
// not "when did the last wheel get added."
func (p *PyPI) PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error) {
	status, doc, err := p.fetchPackage(ctx, name)
	if err != nil {
		return time.Time{}, err
	}
	if status == http.StatusNotFound || doc == nil {
		return time.Time{}, nil
	}
	if status != http.StatusOK {
		return time.Time{}, fmt.Errorf("pypi publishedAtVersion %s@%s: HTTP %d", name, version, status)
	}
	rel, ok := doc.Releases[version]
	if !ok || len(rel) == 0 {
		return time.Time{}, nil
	}
	var earliest time.Time
	for _, f := range rel {
		t, err := time.Parse(time.RFC3339Nano, f.UploadTime)
		if err != nil {
			continue
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	return earliest, nil
}

// TarballURL returns the URL for the sdist (preferred — covers
// the actual source) of a given version, falling back to the
// first wheel if no sdist is published. Used by the static-pattern
// scanner.
func (p *PyPI) TarballURL(ctx context.Context, name, version string) (string, error) {
	status, doc, err := p.fetchPackage(ctx, name)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK || doc == nil {
		return "", fmt.Errorf("pypi tarballURL %s@%s: HTTP %d", name, version, status)
	}
	rel, ok := doc.Releases[version]
	if !ok || len(rel) == 0 {
		return "", fmt.Errorf("pypi tarballURL %s@%s: version not found", name, version)
	}
	for _, f := range rel {
		if f.Packagetype == "sdist" {
			return f.URL, nil
		}
	}
	return rel[0].URL, nil
}

// PublisherOfVersion returns the project-level maintainer email
// (the only publisher-like identity PyPI exposes in the public
// JSON API). PyPI's "publisher" isn't per-version — the JSON
// endpoint shows the CURRENT maintainer for every release. So
// our publisher-change check effectively becomes: "did the
// project-level maintainer drift since the last known good
// state?". Returns "" + nil when no maintainer field is set
// (very common for older packages), and the gate degrades to
// Unknown for those.
func (p *PyPI) PublisherOfVersion(ctx context.Context, name, version string) (string, error) {
	status, doc, err := p.fetchPackage(ctx, name)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK || doc == nil {
		return "", nil
	}
	// PyPI's `info.maintainer_email` is the project-level
	// maintainer. Falls back to `info.author_email` when the
	// project has never set maintainer explicitly.
	if doc.Info.MaintainerEmail != "" {
		return doc.Info.MaintainerEmail, nil
	}
	return doc.Info.AuthorEmail, nil
}

// AllVersions returns the timeline of every published version for
// the package, chronologically. The Publisher field is filled
// with the project-level maintainer (shared across versions
// because PyPI doesn't expose per-version identity).
func (p *PyPI) AllVersions(ctx context.Context, name string) ([]VersionInfo, error) {
	status, doc, err := p.fetchPackage(ctx, name)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || doc == nil {
		return nil, nil
	}
	publisher := doc.Info.MaintainerEmail
	if publisher == "" {
		publisher = doc.Info.AuthorEmail
	}
	out := make([]VersionInfo, 0, len(doc.Releases))
	for ver, files := range doc.Releases {
		if len(files) == 0 {
			continue
		}
		// Earliest upload time across files for this version.
		var earliest time.Time
		for _, f := range files {
			t, err := time.Parse(time.RFC3339Nano, f.UploadTime)
			if err != nil {
				continue
			}
			if earliest.IsZero() || t.Before(earliest) {
				earliest = t
			}
		}
		out = append(out, VersionInfo{
			Name:        name,
			Version:     ver,
			Publisher:   publisher,
			PublishedAt: earliest,
		})
	}
	sortVersionsByPublishedAt(out)
	return out, nil
}

// FetchTarball downloads a release file. Mirror of the npm probe's
// FetchTarball — both produce a gzipped archive the static-pattern
// scanner can walk (.tar.gz for sdist, .zip for wheel).
func (p *PyPI) FetchTarball(ctx context.Context, url string, dst io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if p.UserAgent != "" {
		req.Header.Set("User-Agent", p.UserAgent)
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tarball %s: HTTP %d", url, resp.StatusCode)
	}
	_, err = io.Copy(dst, io.LimitReader(resp.Body, 50<<20))
	return err
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
