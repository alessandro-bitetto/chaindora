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

// Hex is the Erlang/Elixir package registry. The HTTP API:
//   - GET hex.pm/api/packages/<name>
//     → top-level metadata + list of releases (version + insert_at)
//   - GET hex.pm/api/packages/<name>/releases/<version>
//     → per-release blob with publisher + checksum
//
// Tarballs live at:
//   - GET repo.hex.pm/tarballs/<name>-<version>.tar
type Hex struct {
	Client    *http.Client
	APIURL    string // default: https://hex.pm/api
	RepoURL   string // default: https://repo.hex.pm
	UserAgent string
}

func NewHex() *Hex {
	return &Hex{
		Client:    &http.Client{Timeout: 10 * time.Second},
		APIURL:    "https://hex.pm/api",
		RepoURL:   "https://repo.hex.pm",
		UserAgent: "chdora-registry/",
	}
}

type hexPackageDoc struct {
	Name     string       `json:"name"`
	Releases []hexRelease `json:"releases"`
}

type hexRelease struct {
	Version  string `json:"version"`
	InsertAt string `json:"inserted_at"`
}

type hexReleaseDoc struct {
	Version   string         `json:"version"`
	InsertAt  string         `json:"inserted_at"`
	Publisher *hexPublisher  `json:"publisher,omitempty"`
}

type hexPublisher struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

func (h *Hex) fetchPackage(ctx context.Context, name string) (*hexPackageDoc, error) {
	u := strings.TrimRight(h.APIURL, "/") + "/packages/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if h.UserAgent != "" {
		req.Header.Set("User-Agent", h.UserAgent)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hex %s: HTTP %d", name, resp.StatusCode)
	}
	var doc hexPackageDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	sort.Slice(doc.Releases, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339, doc.Releases[i].InsertAt)
		tj, _ := time.Parse(time.RFC3339, doc.Releases[j].InsertAt)
		return ti.Before(tj)
	})
	return &doc, nil
}

func (h *Hex) fetchRelease(ctx context.Context, name, version string) (*hexReleaseDoc, error) {
	u := strings.TrimRight(h.APIURL, "/") + "/packages/" + url.PathEscape(name) + "/releases/" + url.PathEscape(version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if h.UserAgent != "" {
		req.Header.Set("User-Agent", h.UserAgent)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hex %s@%s: HTTP %d", name, version, resp.StatusCode)
	}
	var doc hexReleaseDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func (h *Hex) PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error) {
	doc, err := h.fetchPackage(ctx, name)
	if err != nil || doc == nil {
		return time.Time{}, err
	}
	for _, r := range doc.Releases {
		if r.Version == version {
			t, _ := time.Parse(time.RFC3339, r.InsertAt)
			return t, nil
		}
	}
	return time.Time{}, nil
}

func (h *Hex) PublisherOfVersion(ctx context.Context, name, version string) (string, error) {
	rel, err := h.fetchRelease(ctx, name, version)
	if err != nil || rel == nil || rel.Publisher == nil {
		return "", err
	}
	if rel.Publisher.Username != "" {
		return rel.Publisher.Username, nil
	}
	return rel.Publisher.Email, nil
}

func (h *Hex) AllVersions(ctx context.Context, name string) ([]VersionInfo, error) {
	doc, err := h.fetchPackage(ctx, name)
	if err != nil || doc == nil {
		return nil, err
	}
	out := make([]VersionInfo, 0, len(doc.Releases))
	for _, r := range doc.Releases {
		t, _ := time.Parse(time.RFC3339, r.InsertAt)
		out = append(out, VersionInfo{
			Name:        name,
			Version:     r.Version,
			PublishedAt: t,
		})
	}
	return out, nil
}

func (h *Hex) TarballURL(ctx context.Context, name, version string) (string, error) {
	return fmt.Sprintf("%s/tarballs/%s-%s.tar",
		strings.TrimRight(h.RepoURL, "/"),
		url.PathEscape(name),
		url.PathEscape(version)), nil
}

func (h *Hex) FetchTarball(ctx context.Context, fetchURL string, dst io.Writer) error {
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
