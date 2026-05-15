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

// NPM is a Probe backed by registry.npmjs.org + api.npmjs.org.
// Two endpoints we use:
//   - GET registry.npmjs.org/<encoded-name>     — package metadata, exists check, publish dates
//   - GET api.npmjs.org/downloads/point/last-week/<encoded-name>  — download counts
//
// npm allows ~60 unauthenticated requests/minute per IP and much more
// with a token. We don't authenticate; the cache layer keeps us well
// under the limit for any sane audit (~50 distinct packages probed
// per machine-wide run).
type NPM struct {
	Client       *http.Client
	RegistryURL  string // default: https://registry.npmjs.org
	DownloadsURL string // default: https://api.npmjs.org/downloads/point/last-week
	UserAgent    string
}

// NewNPM returns a probe configured for the default public registry. Override
// the URLs in tests with httptest.Server addresses.
func NewNPM() *NPM {
	return &NPM{
		Client:       &http.Client{Timeout: 10 * time.Second},
		RegistryURL:  "https://registry.npmjs.org",
		DownloadsURL: "https://api.npmjs.org/downloads/point/last-week",
		UserAgent:    "chdora-registry/",
	}
}

type npmPackageDoc struct {
	Time map[string]string `json:"time"` // version → ISO8601 publish date; "created" / "modified" reserved keys
}

func (n *NPM) Exists(ctx context.Context, name string) (bool, error) {
	status, _, err := n.fetchPackage(ctx, name)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("npm exists %s: HTTP %d", name, status)
	}
}

func (n *NPM) PublishedAt(ctx context.Context, name string) (time.Time, error) {
	status, doc, err := n.fetchPackage(ctx, name)
	if err != nil {
		return time.Time{}, err
	}
	if status == http.StatusNotFound {
		return time.Time{}, nil
	}
	if status != http.StatusOK {
		return time.Time{}, fmt.Errorf("npm publishedAt %s: HTTP %d", name, status)
	}
	if created, ok := doc.Time["created"]; ok {
		if t, err := time.Parse(time.RFC3339, created); err == nil {
			return t, nil
		}
	}
	return time.Time{}, nil
}

func (n *NPM) DownloadsLast7d(ctx context.Context, name string) (int, error) {
	enc := encodeNPMName(name)
	u := strings.TrimRight(n.DownloadsURL, "/") + "/" + enc
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return -1, err
	}
	if n.UserAgent != "" {
		req.Header.Set("User-Agent", n.UserAgent)
	}
	resp, err := n.Client.Do(req)
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, nil
	}
	if resp.StatusCode != http.StatusOK {
		return -1, fmt.Errorf("npm downloads %s: HTTP %d", name, resp.StatusCode)
	}
	var body struct {
		Downloads int `json:"downloads"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return -1, err
	}
	return body.Downloads, nil
}

func (n *NPM) fetchPackage(ctx context.Context, name string) (int, *npmPackageDoc, error) {
	enc := encodeNPMName(name)
	u := strings.TrimRight(n.RegistryURL, "/") + "/" + enc
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, err
	}
	if n.UserAgent != "" {
		req.Header.Set("User-Agent", n.UserAgent)
	}
	resp, err := n.Client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, nil
	}
	var doc npmPackageDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&doc); err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, &doc, nil
}

// encodeNPMName URL-encodes a package name with the npm-specific convention:
// scoped packages have their "/" encoded as "%2F" but the leading "@"
// stays as-is. Plain names are passed through unchanged.
func encodeNPMName(name string) string {
	if strings.HasPrefix(name, "@") {
		if i := strings.Index(name, "/"); i > 0 {
			return name[:i] + "%2F" + url.PathEscape(name[i+1:])
		}
	}
	return url.PathEscape(name)
}
