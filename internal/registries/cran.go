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

// CRAN is the R package archive. Direct CRAN doesn't expose a JSON
// API but the community-maintained crandb mirror does:
//   - GET crandb.r-pkg.org/<name>            → current release blob
//   - GET crandb.r-pkg.org/<name>/all        → every release historically
//
// Tarballs (.tar.gz source packages) live on the real CRAN at:
//   - GET cloud.r-project.org/src/contrib/<name>_<version>.tar.gz
//     (current)
//   - GET cloud.r-project.org/src/contrib/Archive/<name>/<name>_<version>.tar.gz
//     (historical)
//
// CRAN packages don't expose a per-version publisher account — the
// crandb API surfaces a "Maintainer" field that's a free-text
// "Name <email>" entry inherited from the package DESCRIPTION file.
// We treat the email as the publisher key (stabler across versions).
type CRAN struct {
	Client    *http.Client
	DBURL     string // default: https://crandb.r-pkg.org
	MirrorURL string // default: https://cloud.r-project.org
	UserAgent string
}

func NewCRAN() *CRAN {
	return &CRAN{
		Client:    &http.Client{Timeout: 10 * time.Second},
		DBURL:     "https://crandb.r-pkg.org",
		MirrorURL: "https://cloud.r-project.org",
		UserAgent: "chdora-registry/",
	}
}

type cranAllDoc struct {
	Versions map[string]cranVersion `json:"versions"`
}

type cranVersion struct {
	Version    string `json:"Version"`
	Date       string `json:"Date/Publication"`
	Maintainer string `json:"Maintainer"`
}

func (c *CRAN) fetchAll(ctx context.Context, name string) (*cranAllDoc, error) {
	u := strings.TrimRight(c.DBURL, "/") + "/" + url.PathEscape(name) + "/all"
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
		return nil, fmt.Errorf("cran %s: HTTP %d", name, resp.StatusCode)
	}
	var doc cranAllDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// parseCRANMaintainer extracts the email out of a "Name <email>"
// DESCRIPTION-file field. CRAN normalizes this format. Falls back
// to the whole string if no angle-brackets are present.
func parseCRANMaintainer(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "<"); i >= 0 {
		if j := strings.Index(s[i:], ">"); j > 0 {
			return strings.TrimSpace(s[i+1 : i+j])
		}
	}
	return s
}

func parseCRANDate(s string) time.Time {
	// crandb returns "YYYY-MM-DD HH:MM:SS UTC" or "YYYY-MM-DD".
	for _, layout := range []string{
		"2006-01-02 15:04:05 UTC",
		"2006-01-02 15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t
		}
	}
	return time.Time{}
}

func (c *CRAN) PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error) {
	doc, err := c.fetchAll(ctx, name)
	if err != nil || doc == nil {
		return time.Time{}, err
	}
	if v, ok := doc.Versions[version]; ok {
		return parseCRANDate(v.Date), nil
	}
	return time.Time{}, nil
}

func (c *CRAN) PublisherOfVersion(ctx context.Context, name, version string) (string, error) {
	doc, err := c.fetchAll(ctx, name)
	if err != nil || doc == nil {
		return "", err
	}
	if v, ok := doc.Versions[version]; ok {
		return parseCRANMaintainer(v.Maintainer), nil
	}
	return "", nil
}

func (c *CRAN) AllVersions(ctx context.Context, name string) ([]VersionInfo, error) {
	doc, err := c.fetchAll(ctx, name)
	if err != nil || doc == nil {
		return nil, err
	}
	out := make([]VersionInfo, 0, len(doc.Versions))
	for v, info := range doc.Versions {
		out = append(out, VersionInfo{
			Name:        name,
			Version:     v,
			Publisher:   parseCRANMaintainer(info.Maintainer),
			PublishedAt: parseCRANDate(info.Date),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublishedAt.Before(out[j].PublishedAt) })
	return out, nil
}

func (c *CRAN) TarballURL(ctx context.Context, name, version string) (string, error) {
	// Try the current-release path; if the version is archived
	// the caller will get a 404 on FetchTarball and re-request
	// against the Archive/<name>/ subdirectory. To keep TarballURL
	// stateless we return the current-release URL; callers that
	// need the archive URL can construct it themselves.
	return fmt.Sprintf("%s/src/contrib/%s_%s.tar.gz",
		strings.TrimRight(c.MirrorURL, "/"),
		url.PathEscape(name),
		url.PathEscape(version)), nil
}

func (c *CRAN) FetchTarball(ctx context.Context, fetchURL string, dst io.Writer) error {
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
