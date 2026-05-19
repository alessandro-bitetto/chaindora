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

// Conda is the conda/Mamba registry, fronted by anaconda.org for
// the public "conda-forge" channel and other org-scoped channels.
// The HTTP API:
//   - GET api.anaconda.org/package/<channel>/<name>
//     → metadata including a `files` list with per-file upload_time,
//       owner, channels[], distribution_type ("conda" / "tar.bz2")
//
// Conda package names look like "channel::name" (e.g.
// "conda-forge::numpy") at lockfile-parse time. Probe expects
// just the name when the channel is encoded separately; if the
// caller hasn't split it we extract.
//
// "Versions" in conda are (version, build_string) pairs — the same
// version 1.2.3 may have multiple builds (py39_0, py310_0, etc.).
// We aggregate to the version level for the gate's purposes, using
// the earliest upload_time across builds.
type Conda struct {
	Client         *http.Client
	BaseURL        string // default: https://api.anaconda.org
	DefaultChannel string // default: "conda-forge"
	UserAgent      string
}

func NewConda() *Conda {
	return &Conda{
		Client:         &http.Client{Timeout: 10 * time.Second},
		BaseURL:        "https://api.anaconda.org",
		DefaultChannel: "conda-forge",
		UserAgent:      "chdora-registry/",
	}
}

type condaPackageDoc struct {
	Name  string        `json:"name"`
	Files []condaFile   `json:"files"`
	Owner condaOwner    `json:"owner"`
}

type condaFile struct {
	Version          string `json:"version"`
	Build            string `json:"attrs.build"`
	UploadTime       string `json:"upload_time"`
	Owner            string `json:"owner"`
	DownloadURL      string `json:"download_url"`
}

type condaOwner struct {
	Login string `json:"login"`
	Name  string `json:"name"`
}

// splitChannelName accepts "conda-forge::numpy" and returns
// ("conda-forge", "numpy"); for "numpy" returns (defaultChannel,
// "numpy").
func (c *Conda) splitChannelName(name string) (string, string) {
	if i := strings.Index(name, "::"); i > 0 {
		return name[:i], name[i+2:]
	}
	return c.DefaultChannel, name
}

func (c *Conda) fetchPackage(ctx context.Context, name string) (*condaPackageDoc, error) {
	channel, pkg := c.splitChannelName(name)
	u := strings.TrimRight(c.BaseURL, "/") + "/package/" + url.PathEscape(channel) + "/" + url.PathEscape(pkg)
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
		return nil, fmt.Errorf("conda %s: HTTP %d", name, resp.StatusCode)
	}
	var doc condaPackageDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func parseCondaTime(s string) time.Time {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func (c *Conda) PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error) {
	doc, err := c.fetchPackage(ctx, name)
	if err != nil || doc == nil {
		return time.Time{}, err
	}
	// Earliest upload across all builds of this version.
	var earliest time.Time
	for _, f := range doc.Files {
		if f.Version != version {
			continue
		}
		t := parseCondaTime(f.UploadTime)
		if t.IsZero() {
			continue
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	return earliest, nil
}

func (c *Conda) PublisherOfVersion(ctx context.Context, name, version string) (string, error) {
	doc, err := c.fetchPackage(ctx, name)
	if err != nil || doc == nil {
		return "", err
	}
	// Per-file uploader; fall back to the package owner.
	for _, f := range doc.Files {
		if f.Version == version && f.Owner != "" {
			return f.Owner, nil
		}
	}
	if doc.Owner.Login != "" {
		return doc.Owner.Login, nil
	}
	return doc.Owner.Name, nil
}

func (c *Conda) AllVersions(ctx context.Context, name string) ([]VersionInfo, error) {
	doc, err := c.fetchPackage(ctx, name)
	if err != nil || doc == nil {
		return nil, err
	}
	// Collapse multiple builds per version to one VersionInfo,
	// keeping the earliest upload time.
	byVersion := map[string]VersionInfo{}
	for _, f := range doc.Files {
		t := parseCondaTime(f.UploadTime)
		v, ok := byVersion[f.Version]
		if !ok {
			byVersion[f.Version] = VersionInfo{
				Name:        name,
				Version:     f.Version,
				Publisher:   f.Owner,
				PublishedAt: t,
			}
			continue
		}
		if !t.IsZero() && (v.PublishedAt.IsZero() || t.Before(v.PublishedAt)) {
			v.PublishedAt = t
			byVersion[f.Version] = v
		}
	}
	out := make([]VersionInfo, 0, len(byVersion))
	for _, v := range byVersion {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublishedAt.Before(out[j].PublishedAt) })
	return out, nil
}

func (c *Conda) TarballURL(ctx context.Context, name, version string) (string, error) {
	doc, err := c.fetchPackage(ctx, name)
	if err != nil || doc == nil {
		return "", err
	}
	// Conda packages have a (version, build) tuple — return the
	// first matching file's download URL. Callers iterating
	// builds should use AllVersions and walk doc.Files themselves.
	for _, f := range doc.Files {
		if f.Version == version && f.DownloadURL != "" {
			return f.DownloadURL, nil
		}
	}
	return "", nil
}

func (c *Conda) FetchTarball(ctx context.Context, fetchURL string, dst io.Writer) error {
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
	_, err = io.Copy(dst, io.LimitReader(resp.Body, 200<<20))
	return err
}
