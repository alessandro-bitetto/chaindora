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

// CocoaPods is the iOS/macOS package registry. The trunk API:
//   - GET trunk.cocoapods.org/api/v1/pods/<name>
//     → { "versions": [ { "name": "...", "created_at": "..." }, ... ],
//          "owners": [ { "email": "...", "name": "..." }, ... ] }
//
// CocoaPods doesn't host source archives — it hosts .podspec files
// that point at git repos / external archives. The "tarball" for a
// pod is effectively the .podspec.json:
//   - GET trunk.cocoapods.org/api/v1/pods/<name>/specs/<version>.json
//
// No per-version publisher — owners are project-level. We use the
// first owner email as the publisher key.
type CocoaPods struct {
	Client    *http.Client
	BaseURL   string // default: https://trunk.cocoapods.org/api/v1
	UserAgent string
}

func NewCocoaPods() *CocoaPods {
	return &CocoaPods{
		Client:    &http.Client{Timeout: 10 * time.Second},
		BaseURL:   "https://trunk.cocoapods.org/api/v1",
		UserAgent: "chdora-registry/",
	}
}

type cocoapodsDoc struct {
	Name     string             `json:"name"`
	Versions []cocoapodsVersion `json:"versions"`
	Owners   []cocoapodsOwner   `json:"owners"`
}

type cocoapodsVersion struct {
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

type cocoapodsOwner struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (c *CocoaPods) fetchPod(ctx context.Context, name string) (*cocoapodsDoc, error) {
	u := strings.TrimRight(c.BaseURL, "/") + "/pods/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
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
		return nil, fmt.Errorf("cocoapods %s: HTTP %d", name, resp.StatusCode)
	}
	var doc cocoapodsDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	sort.Slice(doc.Versions, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339Nano, doc.Versions[i].CreatedAt)
		tj, _ := time.Parse(time.RFC3339Nano, doc.Versions[j].CreatedAt)
		return ti.Before(tj)
	})
	return &doc, nil
}

func (c *CocoaPods) PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error) {
	doc, err := c.fetchPod(ctx, name)
	if err != nil || doc == nil {
		return time.Time{}, err
	}
	for _, v := range doc.Versions {
		if v.Name == version {
			t, _ := time.Parse(time.RFC3339Nano, v.CreatedAt)
			return t, nil
		}
	}
	return time.Time{}, nil
}

func (c *CocoaPods) PublisherOfVersion(ctx context.Context, name, version string) (string, error) {
	doc, err := c.fetchPod(ctx, name)
	if err != nil || doc == nil || len(doc.Owners) == 0 {
		return "", err
	}
	o := doc.Owners[0]
	if o.Email != "" {
		return o.Email, nil
	}
	return o.Name, nil
}

func (c *CocoaPods) AllVersions(ctx context.Context, name string) ([]VersionInfo, error) {
	doc, err := c.fetchPod(ctx, name)
	if err != nil || doc == nil {
		return nil, err
	}
	publisher := ""
	if len(doc.Owners) > 0 {
		publisher = doc.Owners[0].Email
		if publisher == "" {
			publisher = doc.Owners[0].Name
		}
	}
	out := make([]VersionInfo, 0, len(doc.Versions))
	for _, v := range doc.Versions {
		t, _ := time.Parse(time.RFC3339Nano, v.CreatedAt)
		out = append(out, VersionInfo{
			Name:        name,
			Version:     v.Name,
			Publisher:   publisher,
			PublishedAt: t,
		})
	}
	return out, nil
}

func (c *CocoaPods) TarballURL(ctx context.Context, name, version string) (string, error) {
	// The closest thing to a tarball for CocoaPods is the
	// .podspec.json — that's where source.git / source.http
	// pointers live for the actual sources.
	return fmt.Sprintf("%s/pods/%s/specs/%s.json",
		strings.TrimRight(c.BaseURL, "/"),
		url.PathEscape(name),
		url.PathEscape(version)), nil
}

func (c *CocoaPods) FetchTarball(ctx context.Context, fetchURL string, dst io.Writer) error {
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
		return fmt.Errorf("podspec %s: HTTP %d", fetchURL, resp.StatusCode)
	}
	_, err = io.Copy(dst, io.LimitReader(resp.Body, 4<<20))
	return err
}
