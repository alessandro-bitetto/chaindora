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

// Crates probes crates.io/api/v1. The endpoint shape:
//   /api/v1/crates/<name>           → top-level + version list with
//                                     publish dates
//   /api/v1/crates/<name>/<version> → per-version details
//   /api/v1/crates/<name>/owners    → owner list (the closest thing
//                                     to a per-version publisher)
//
// Tarballs ("crate files") live at:
//   /api/v1/crates/<name>/<version>/download
//
// Crates' "owners" model isn't per-version — once you're an owner
// you can publish any version. We use the owner list as the
// project-level publisher and treat owner-set changes as the
// publisher-change signal.
type Crates struct {
	Client    *http.Client
	BaseURL   string // default: https://crates.io/api/v1
	UserAgent string
}

func NewCrates() *Crates {
	return &Crates{
		Client:    &http.Client{Timeout: 10 * time.Second},
		BaseURL:   "https://crates.io/api/v1",
		// crates.io enforces a User-Agent that includes contact
		// info. We can't include a real address here so the
		// generic project URL substitutes.
		UserAgent: "chdora-registry (https://github.com/alessandro-bitetto/chaindora)",
	}
}

type cratesCrateDoc struct {
	Crate    cratesCrateInfo    `json:"crate"`
	Versions []cratesVersionDoc `json:"versions"`
}

type cratesCrateInfo struct {
	ID         string `json:"id"`
	Repository string `json:"repository"`
}

type cratesVersionDoc struct {
	Num         string `json:"num"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	DLPath      string `json:"dl_path"`
	PublishedBy *struct {
		Login string `json:"login"`
		Name  string `json:"name"`
	} `json:"published_by"`
	Yanked bool `json:"yanked"`
}

func (c *Crates) fetchCrate(ctx context.Context, name string) (*cratesCrateDoc, int, error) {
	u := strings.TrimRight(c.BaseURL, "/") + "/crates/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("crates %s: HTTP %d", name, resp.StatusCode)
	}
	var doc cratesCrateDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&doc); err != nil {
		return nil, resp.StatusCode, err
	}
	// Sort oldest-first to match other ecosystems.
	sort.Slice(doc.Versions, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339Nano, doc.Versions[i].CreatedAt)
		tj, _ := time.Parse(time.RFC3339Nano, doc.Versions[j].CreatedAt)
		return ti.Before(tj)
	})
	return &doc, resp.StatusCode, nil
}

func (c *Crates) PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error) {
	doc, _, err := c.fetchCrate(ctx, name)
	if err != nil || doc == nil {
		return time.Time{}, err
	}
	for _, v := range doc.Versions {
		if v.Num == version {
			t, _ := time.Parse(time.RFC3339Nano, v.CreatedAt)
			return t, nil
		}
	}
	return time.Time{}, nil
}

func (c *Crates) PublisherOfVersion(ctx context.Context, name, version string) (string, error) {
	doc, _, err := c.fetchCrate(ctx, name)
	if err != nil || doc == nil {
		return "", err
	}
	for _, v := range doc.Versions {
		if v.Num == version && v.PublishedBy != nil {
			if v.PublishedBy.Login != "" {
				return v.PublishedBy.Login, nil
			}
			return v.PublishedBy.Name, nil
		}
	}
	return "", nil
}

func (c *Crates) AllVersions(ctx context.Context, name string) ([]VersionInfo, error) {
	doc, _, err := c.fetchCrate(ctx, name)
	if err != nil || doc == nil {
		return nil, err
	}
	out := make([]VersionInfo, 0, len(doc.Versions))
	for _, v := range doc.Versions {
		if v.Yanked {
			continue
		}
		t, _ := time.Parse(time.RFC3339Nano, v.CreatedAt)
		publisher := ""
		if v.PublishedBy != nil {
			publisher = v.PublishedBy.Login
		}
		out = append(out, VersionInfo{
			Name:        name,
			Version:     v.Num,
			Publisher:   publisher,
			PublishedAt: t,
		})
	}
	return out, nil
}

func (c *Crates) TarballURL(ctx context.Context, name, version string) (string, error) {
	doc, _, err := c.fetchCrate(ctx, name)
	if err != nil || doc == nil {
		// The CDN URL is deterministic enough to construct
		// without a metadata fetch, used as fallback.
		return fmt.Sprintf("%s/crates/%s/%s/download", strings.TrimRight(c.BaseURL, "/"), url.PathEscape(name), url.PathEscape(version)), nil
	}
	for _, v := range doc.Versions {
		if v.Num == version && v.DLPath != "" {
			// dl_path is relative ("/api/v1/crates/X/Y/download"); resolve.
			if strings.HasPrefix(v.DLPath, "/") {
				host := strings.TrimSuffix(strings.TrimSuffix(c.BaseURL, "/api/v1"), "/")
				return host + v.DLPath, nil
			}
			return v.DLPath, nil
		}
	}
	return fmt.Sprintf("%s/crates/%s/%s/download", strings.TrimRight(c.BaseURL, "/"), url.PathEscape(name), url.PathEscape(version)), nil
}

// HasProvenance: crates.io exposes `published_by` per version
// (already the publisher-change signal). When present + non-
// nil, it means the publish was authenticated against a
// crates.io account — the platform's attribution layer. Not
// sigstore-grade (cargo trusted-publishing is in development),
// but it's the strongest signal the API exposes today.
func (c *Crates) HasProvenance(ctx context.Context, name, version string) (bool, error) {
	doc, _, err := c.fetchCrate(ctx, name)
	if err != nil || doc == nil {
		return false, err
	}
	for _, v := range doc.Versions {
		if v.Num == version && v.PublishedBy != nil && v.PublishedBy.Login != "" {
			return true, nil
		}
	}
	return false, nil
}

// AnyVersionHasProvenance: at least one version must record a
// publisher account. crates.io has had `published_by` since
// 2018, so this is almost always true for actively maintained
// crates — the regression case (some versions have it, this
// one doesn't) is the real signal.
func (c *Crates) AnyVersionHasProvenance(ctx context.Context, name string) (bool, error) {
	doc, _, err := c.fetchCrate(ctx, name)
	if err != nil || doc == nil {
		return false, err
	}
	for _, v := range doc.Versions {
		if v.PublishedBy != nil && v.PublishedBy.Login != "" {
			return true, nil
		}
	}
	return false, nil
}

func (c *Crates) FetchTarball(ctx context.Context, fetchURL string, dst io.Writer) error {
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
