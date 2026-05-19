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

// Pub is the Dart/Flutter package registry at pub.dev. The HTTP API:
//   - GET pub.dev/api/packages/<name>
//     → metadata for every published version + publisher info
//   - GET pub.dev/api/packages/<name>/publisher
//     → verified-publisher object (publisher_id) for the whole
//     package
//
// Publishers in pub.dev are organization-scoped (e.g. "google.dev",
// "flutter.dev") and apply to the package as a whole, not per
// version. Per-version uploader info is in the `pubspec.publisher`
// hint but not always set. We use the package-level publisher_id as
// the publisher signal — a publisher_id change (or appearing /
// disappearing) is a real handoff signal.
type Pub struct {
	Client    *http.Client
	BaseURL   string // default: https://pub.dev
	UserAgent string
}

func NewPub() *Pub {
	return &Pub{
		Client:    &http.Client{Timeout: 10 * time.Second},
		BaseURL:   "https://pub.dev",
		UserAgent: "chdora-registry/",
	}
}

type pubPackageDoc struct {
	Name     string       `json:"name"`
	Versions []pubVersion `json:"versions"`
}

type pubVersion struct {
	Version    string                 `json:"version"`
	Published  string                 `json:"published"`
	ArchiveURL string                 `json:"archive_url"`
	Pubspec    map[string]interface{} `json:"pubspec"`
}

func (p *Pub) fetchPackage(ctx context.Context, name string) (*pubPackageDoc, error) {
	u := strings.TrimRight(p.BaseURL, "/") + "/api/packages/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if p.UserAgent != "" {
		req.Header.Set("User-Agent", p.UserAgent)
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pub %s: HTTP %d", name, resp.StatusCode)
	}
	var doc pubPackageDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	sort.Slice(doc.Versions, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339Nano, doc.Versions[i].Published)
		tj, _ := time.Parse(time.RFC3339Nano, doc.Versions[j].Published)
		return ti.Before(tj)
	})
	return &doc, nil
}

func (p *Pub) fetchPublisher(ctx context.Context, name string) (string, error) {
	u := strings.TrimRight(p.BaseURL, "/") + "/api/packages/" + url.PathEscape(name) + "/publisher"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	if p.UserAgent != "" {
		req.Header.Set("User-Agent", p.UserAgent)
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}
	var body struct {
		PublisherID string `json:"publisherId"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		return "", err
	}
	return body.PublisherID, nil
}

func (p *Pub) PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error) {
	doc, err := p.fetchPackage(ctx, name)
	if err != nil || doc == nil {
		return time.Time{}, err
	}
	for _, v := range doc.Versions {
		if v.Version == version {
			t, _ := time.Parse(time.RFC3339Nano, v.Published)
			return t, nil
		}
	}
	return time.Time{}, nil
}

func (p *Pub) PublisherOfVersion(ctx context.Context, name, version string) (string, error) {
	doc, err := p.fetchPackage(ctx, name)
	if err != nil || doc == nil {
		return "", err
	}
	// Per-version hint first (pubspec.publisher), then package-level
	// publisher_id fallback. The package-level publisher is the
	// stronger signal because pub.dev verifies it via domain ownership.
	for _, v := range doc.Versions {
		if v.Version == version {
			if pub, ok := v.Pubspec["publisher"].(string); ok && pub != "" {
				return pub, nil
			}
		}
	}
	return p.fetchPublisher(ctx, name)
}

func (p *Pub) AllVersions(ctx context.Context, name string) ([]VersionInfo, error) {
	doc, err := p.fetchPackage(ctx, name)
	if err != nil || doc == nil {
		return nil, err
	}
	publisher, _ := p.fetchPublisher(ctx, name)
	out := make([]VersionInfo, 0, len(doc.Versions))
	for _, v := range doc.Versions {
		t, _ := time.Parse(time.RFC3339Nano, v.Published)
		ver := VersionInfo{
			Name:        name,
			Version:     v.Version,
			Publisher:   publisher,
			PublishedAt: t,
		}
		if pub, ok := v.Pubspec["publisher"].(string); ok && pub != "" {
			ver.Publisher = pub
		}
		out = append(out, ver)
	}
	return out, nil
}

func (p *Pub) TarballURL(ctx context.Context, name, version string) (string, error) {
	doc, err := p.fetchPackage(ctx, name)
	if err != nil || doc == nil {
		return "", err
	}
	for _, v := range doc.Versions {
		if v.Version == version && v.ArchiveURL != "" {
			return v.ArchiveURL, nil
		}
	}
	return "", nil
}

func (p *Pub) FetchTarball(ctx context.Context, fetchURL string, dst io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
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
		return fmt.Errorf("tarball %s: HTTP %d", fetchURL, resp.StatusCode)
	}
	_, err = io.Copy(dst, io.LimitReader(resp.Body, 50<<20))
	return err
}
