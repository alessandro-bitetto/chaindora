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

// Packagist is the PHP/Composer registry. The metadata HTTP API:
//   - GET repo.packagist.org/p2/<vendor>/<name>.json
//     → array of all NON-dev versions with publish dates + authors
//   - GET repo.packagist.org/p2/<vendor>/<name>~dev.json
//     → array of dev branches (HEAD versions like "dev-main") —
//     not relevant for the gate, we don't ingest these.
//
// Tarballs live on Composer's "dist" URLs (GitHub / GitLab archive
// endpoints in most cases) — we pass through the URL the API gives
// us.
type Packagist struct {
	Client    *http.Client
	BaseURL   string // default: https://repo.packagist.org
	UserAgent string
}

func NewPackagist() *Packagist {
	return &Packagist{
		Client:    &http.Client{Timeout: 10 * time.Second},
		BaseURL:   "https://repo.packagist.org",
		UserAgent: "chdora-registry/",
	}
}

type packagistDoc struct {
	Packages map[string][]packagistVersion `json:"packages"`
}

type packagistVersion struct {
	Name    string             `json:"name"`
	Version string             `json:"version"`
	Time    string             `json:"time"`
	Authors []packagistAuthor  `json:"authors"`
	Dist    *packagistDist     `json:"dist,omitempty"`
}

type packagistAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type packagistDist struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

func (p *Packagist) fetchPackage(ctx context.Context, name string) ([]packagistVersion, error) {
	// Composer names are vendor/name — both segments are URL-safe.
	u := strings.TrimRight(p.BaseURL, "/") + "/p2/" + name + ".json"
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
		return nil, fmt.Errorf("packagist %s: HTTP %d", name, resp.StatusCode)
	}
	var doc packagistDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	versions := doc.Packages[name]
	sort.Slice(versions, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339, versions[i].Time)
		tj, _ := time.Parse(time.RFC3339, versions[j].Time)
		return ti.Before(tj)
	})
	return versions, nil
}

func (p *Packagist) PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error) {
	vs, err := p.fetchPackage(ctx, name)
	if err != nil {
		return time.Time{}, err
	}
	for _, v := range vs {
		if v.Version == version {
			t, _ := time.Parse(time.RFC3339, v.Time)
			return t, nil
		}
	}
	return time.Time{}, nil
}

func (p *Packagist) PublisherOfVersion(ctx context.Context, name, version string) (string, error) {
	vs, err := p.fetchPackage(ctx, name)
	if err != nil {
		return "", err
	}
	for _, v := range vs {
		if v.Version != version {
			continue
		}
		if len(v.Authors) == 0 {
			return "", nil
		}
		// First author's email is the stablest cross-version key
		// (display names get edited; email accounts get rotated
		// less often). Fall back to display name when email is
		// absent.
		a := v.Authors[0]
		if a.Email != "" {
			return a.Email, nil
		}
		return a.Name, nil
	}
	return "", nil
}

func (p *Packagist) AllVersions(ctx context.Context, name string) ([]VersionInfo, error) {
	vs, err := p.fetchPackage(ctx, name)
	if err != nil {
		return nil, err
	}
	out := make([]VersionInfo, 0, len(vs))
	for _, v := range vs {
		// Skip dev-* branches; they're moving refs, not releases.
		if strings.HasPrefix(v.Version, "dev-") {
			continue
		}
		t, _ := time.Parse(time.RFC3339, v.Time)
		publisher := ""
		if len(v.Authors) > 0 {
			publisher = v.Authors[0].Email
			if publisher == "" {
				publisher = v.Authors[0].Name
			}
		}
		out = append(out, VersionInfo{
			Name:        name,
			Version:     v.Version,
			Publisher:   publisher,
			PublishedAt: t,
		})
	}
	return out, nil
}

func (p *Packagist) TarballURL(ctx context.Context, name, version string) (string, error) {
	vs, err := p.fetchPackage(ctx, name)
	if err != nil {
		return "", err
	}
	for _, v := range vs {
		if v.Version == version && v.Dist != nil && v.Dist.URL != "" {
			return v.Dist.URL, nil
		}
	}
	return "", nil
}

func (p *Packagist) FetchTarball(ctx context.Context, fetchURL string, dst io.Writer) error {
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

// avoid unused-import lint when url is only used in helpers above
var _ = url.PathEscape
