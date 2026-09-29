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

// NuGet probes api.nuget.org v3 endpoints. NuGet's HTTP API splits
// the metadata across several services:
//   - /v3-flatcontainer/<id-lower>/index.json
//     → catalog of all versions for a package id (semver-sorted by
//       the registry, but we re-sort by publish-date for cross-eco
//       consistency)
//   - /v3/registration5-semver1/<id-lower>/<version>.json
//     → per-version metadata: publish date, listed flag, authors,
//       license, dependencies. NuGet calls this the "registration
//       blob"; one HTTP fetch per (name, version).
//   - /v3-flatcontainer/<id-lower>/<version>/<id-lower>.nupkg
//     → the actual package archive (a renamed .zip)
//
// NuGet has no per-version publisher metadata at the API level —
// only "authors" (a free-text package.nuspec field) and an
// account-bound owner list available only through the website.
// PublisherOfVersion therefore returns the first authors entry,
// which is enough for the publisher-change checker to spot the
// shape "previous version: 'JaneDoe', this version: 'Jane Doe
// <attacker@evil.com>'" — the classic post-takeover authorship
// change.
type NuGet struct {
	Client    *http.Client
	BaseURL   string // default: https://api.nuget.org
	UserAgent string
}

// NewNuGet returns a probe configured for the default public registry.
func NewNuGet() *NuGet {
	return &NuGet{
		Client:    &http.Client{Timeout: 10 * time.Second},
		BaseURL:   "https://api.nuget.org",
		UserAgent: "chdora-registry/",
	}
}

// nugetFlatContainerIndex is the response shape of
// /v3-flatcontainer/<id>/index.json — a simple list of every
// published version, semver-sorted.
type nugetFlatContainerIndex struct {
	Versions []string `json:"versions"`
}

// nugetRegistrationLeaf is the per-version blob served at
// /v3/registration5-semver1/<id>/<version>.json. Real-world API
// behavior: catalogEntry can be either an inline object OR a URL
// string pointing at the actual catalog entry stored on the
// catalog0 service. The fixtures in tests use the inline form;
// the public registry uses the URL form. We accept both.
type nugetRegistrationLeaf struct {
	CatalogEntry json.RawMessage `json:"catalogEntry"`
}

type nugetCatalogEntry struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	Published string `json:"published"`
	Authors   string `json:"authors"`
	Listed    bool   `json:"listed"`
}

func (n *NuGet) fetchVersions(ctx context.Context, name string) ([]string, error) {
	id := strings.ToLower(name)
	u := strings.TrimRight(n.BaseURL, "/") + "/v3-flatcontainer/" + url.PathEscape(id) + "/index.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if n.UserAgent != "" {
		req.Header.Set("User-Agent", n.UserAgent)
	}
	resp, err := n.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nuget %s: HTTP %d", name, resp.StatusCode)
	}
	var idx nugetFlatContainerIndex
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&idx); err != nil {
		return nil, err
	}
	return idx.Versions, nil
}

func (n *NuGet) fetchJSON(ctx context.Context, u string, dst interface{}) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	if n.UserAgent != "" {
		req.Header.Set("User-Agent", n.UserAgent)
	}
	resp, err := n.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("nuget %s: HTTP %d", u, resp.StatusCode)
	}
	return resp.StatusCode, json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(dst)
}

func (n *NuGet) fetchLeaf(ctx context.Context, name, version string) (*nugetCatalogEntry, error) {
	id := strings.ToLower(name)
	v := strings.ToLower(version)
	u := strings.TrimRight(n.BaseURL, "/") + "/v3/registration5-semver1/" + url.PathEscape(id) + "/" + url.PathEscape(v) + ".json"
	var leaf nugetRegistrationLeaf
	status, err := n.fetchJSON(ctx, u, &leaf)
	if err != nil || status == http.StatusNotFound || len(leaf.CatalogEntry) == 0 {
		return nil, err
	}
	// Two response shapes: inline object or URL string. Decode
	// either form into the same struct.
	if len(leaf.CatalogEntry) > 0 && leaf.CatalogEntry[0] == '"' {
		var refURL string
		if err := json.Unmarshal(leaf.CatalogEntry, &refURL); err != nil {
			return nil, err
		}
		var entry nugetCatalogEntry
		if _, err := n.fetchJSON(ctx, refURL, &entry); err != nil {
			return nil, err
		}
		return &entry, nil
	}
	var entry nugetCatalogEntry
	if err := json.Unmarshal(leaf.CatalogEntry, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (n *NuGet) PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error) {
	leaf, err := n.fetchLeaf(ctx, name, version)
	if err != nil || leaf == nil {
		return time.Time{}, err
	}
	t, _ := time.Parse(time.RFC3339Nano, leaf.Published)
	// NuGet marks "unlisted" packages with a sentinel 1900-01-01
	// published date. Treat that as zero so the cooldown checker
	// doesn't fire on every legitimately-unlisted historical version.
	if t.Year() < 2000 {
		return time.Time{}, nil
	}
	return t, nil
}

func (n *NuGet) PublisherOfVersion(ctx context.Context, name, version string) (string, error) {
	leaf, err := n.fetchLeaf(ctx, name, version)
	if err != nil || leaf == nil {
		return "", err
	}
	// "Authors" is a comma-separated free-text field. Use the
	// first entry as the publisher proxy — it's stable enough
	// across versions for the change-detection heuristic.
	first := leaf.Authors
	if i := strings.Index(first, ","); i > 0 {
		first = first[:i]
	}
	return strings.TrimSpace(first), nil
}

func (n *NuGet) AllVersions(ctx context.Context, name string) ([]VersionInfo, error) {
	versions, err := n.fetchVersions(ctx, name)
	if err != nil || len(versions) == 0 {
		return nil, err
	}
	// One leaf fetch per version would be O(N) HTTP — for a long
	// history (Newtonsoft.Json has 100+ versions) that's slow.
	// Keep it pragmatic: return the list with only Version filled
	// so cardinality-based checkers (maintainer-trust's version
	// count) still work, and let cooldown / publisher-change do
	// their own per-version leaf fetches for the specific versions
	// they care about.
	out := make([]VersionInfo, 0, len(versions))
	for _, v := range versions {
		out = append(out, VersionInfo{
			Name:    name,
			Version: v,
		})
	}
	return out, nil
}

func (n *NuGet) TarballURL(ctx context.Context, name, version string) (string, error) {
	id := strings.ToLower(name)
	v := strings.ToLower(version)
	return fmt.Sprintf("%s/v3-flatcontainer/%s/%s/%s.%s.nupkg",
		strings.TrimRight(n.BaseURL, "/"),
		url.PathEscape(id),
		url.PathEscape(v),
		url.PathEscape(id),
		url.PathEscape(v)), nil
}

func (n *NuGet) FetchTarball(ctx context.Context, fetchURL string, dst io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return err
	}
	if n.UserAgent != "" {
		req.Header.Set("User-Agent", n.UserAgent)
	}
	resp, err := n.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("nupkg %s: HTTP %d", fetchURL, resp.StatusCode)
	}
	_, err = io.Copy(dst, io.LimitReader(resp.Body, 50<<20))
	return err
}

