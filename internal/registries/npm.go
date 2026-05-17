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
	Time     map[string]string             `json:"time"` // version → ISO8601 publish date; "created" / "modified" reserved keys
	Versions map[string]npmVersionMetadata `json:"versions,omitempty"`
	DistTags struct {
		Latest string `json:"latest"`
	} `json:"dist-tags,omitempty"`
}

// TarballURL returns the registry CDN URL for fetching the
// (compressed) source tarball of a given version. Used by the
// static-pattern scanner to inspect package contents before they
// land in node_modules.
func (n *NPM) TarballURL(ctx context.Context, name, version string) (string, error) {
	status, doc, err := n.fetchPackage(ctx, name)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK || doc == nil {
		return "", fmt.Errorf("npm tarballURL %s@%s: HTTP %d", name, version, status)
	}
	vm, ok := doc.Versions[version]
	if !ok {
		return "", fmt.Errorf("npm tarballURL %s@%s: version not found", name, version)
	}
	if vm.Dist == nil || vm.Dist.Tarball == "" {
		return "", fmt.Errorf("npm tarballURL %s@%s: no dist.tarball", name, version)
	}
	return vm.Dist.Tarball, nil
}

// FetchTarball downloads the version's tarball into a destination
// io.Writer. Caller is responsible for the underlying file/buffer.
// Bounded by HTTP timeout on n.Client; no extra cap here because
// some legitimate packages are quite large (eslint ~5MB).
func (n *NPM) FetchTarball(ctx context.Context, url string, dst io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
		return fmt.Errorf("tarball %s: HTTP %d", url, resp.StatusCode)
	}
	// 50MB cap is generous — biggest legitimate npm package
	// (typescript itself) is ~10MB compressed.
	_, err = io.Copy(dst, io.LimitReader(resp.Body, 50<<20))
	return err
}

// npmVersionMetadata captures the per-version subset we use for
// gate-time checks (publisher, install scripts, dependencies, repo).
// We deliberately don't pull in `dist.shasum` etc. — keeps the
// cache footprint bounded for packages with hundreds of versions.
type npmVersionMetadata struct {
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	NPMUser    *npmAuthor        `json:"_npmUser,omitempty"`
	Author     interface{}       `json:"author,omitempty"`
	Scripts    map[string]string `json:"scripts,omitempty"`
	Repository interface{}       `json:"repository,omitempty"`
	Dist       *npmDist          `json:"dist,omitempty"`
	HasBindGyp bool              `json:"-"` // populated in code if binding.gyp present
}

type npmDist struct {
	Tarball      string             `json:"tarball"`
	Shasum       string             `json:"shasum"`
	Integrity    string             `json:"integrity"`
	Attestations *npmAttestationsRef `json:"attestations,omitempty"`
}

// npmAttestationsRef is the v0.10 npm-provenance metadata block.
// When a publisher runs `npm publish --provenance`, the registry
// records a sigstore-attested bundle reachable via the URL here.
// Absence of this block on a publish-after-2023 package is a
// soft anti-trust signal — adoption is rising but still optional.
//
// The `provenance` field is an OBJECT in the real response
// (predicateType etc.), not a bool — we don't parse its contents
// here, just presence. json.RawMessage lets us tolerate either
// shape without breaking.
type npmAttestationsRef struct {
	URL        string          `json:"url"`
	Provenance json.RawMessage `json:"provenance,omitempty"`
}

// HasProvenance reports whether the given (name, version) carries
// a sigstore provenance attestation per the npm metadata. Returns
// false + nil error when the package exists but lacks attestation
// (the common case today). Errors only for transport/parse
// failures.
func (n *NPM) HasProvenance(ctx context.Context, name, version string) (bool, error) {
	status, doc, err := n.fetchPackage(ctx, name)
	if err != nil {
		return false, err
	}
	if status != http.StatusOK || doc == nil {
		return false, fmt.Errorf("npm provenance %s@%s: HTTP %d", name, version, status)
	}
	vm, ok := doc.Versions[version]
	if !ok {
		return false, nil
	}
	if vm.Dist == nil || vm.Dist.Attestations == nil {
		return false, nil
	}
	return vm.Dist.Attestations.URL != "", nil
}

// AnyVersionHasProvenance reports whether ANY version of the
// package has ever been published with provenance. Used by the
// gate's sigstore checker to decide whether absence-of-provenance
// is suspicious for THIS publisher (some maintainers adopt
// provenance, others don't — we don't want to spam either).
func (n *NPM) AnyVersionHasProvenance(ctx context.Context, name string) (bool, error) {
	status, doc, err := n.fetchPackage(ctx, name)
	if err != nil {
		return false, err
	}
	if status != http.StatusOK || doc == nil {
		return false, nil
	}
	for _, vm := range doc.Versions {
		if vm.Dist != nil && vm.Dist.Attestations != nil && vm.Dist.Attestations.URL != "" {
			return true, nil
		}
	}
	return false, nil
}

// LatestVersionHasProvenance reports whether the LATEST published
// version of the package has provenance. v0.15.2 — used by the
// provenance checker to suppress the "regression" warn when the
// user's version is just outdated relative to a still-attested
// latest release. Real regressions only fire when LATEST also
// lacks attestation.
//
// "Latest" is the version pointed at by the registry's
// `dist-tags.latest` field (npm's authoritative latest), not a
// version-string sort — semver-sort isn't reliable across npm's
// pre-release / version-range conventions.
func (n *NPM) LatestVersionHasProvenance(ctx context.Context, name string) (bool, error) {
	status, doc, err := n.fetchPackage(ctx, name)
	if err != nil {
		return false, err
	}
	if status != http.StatusOK || doc == nil {
		return false, nil
	}
	latest := doc.DistTags.Latest
	if latest == "" {
		return false, nil
	}
	vm, ok := doc.Versions[latest]
	if !ok {
		return false, nil
	}
	if vm.Dist == nil || vm.Dist.Attestations == nil {
		return false, nil
	}
	return vm.Dist.Attestations.URL != "", nil
}

type npmAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// PublishedAtVersion returns the publish timestamp for a specific
// (name, version) pair. Zero time + nil error means "package exists
// but the version isn't in the .time map" (rare — happens for
// recently-yanked versions). The gate's cooldown check uses this:
// if the version is younger than the threshold, the install is
// refused.
func (n *NPM) PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error) {
	status, doc, err := n.fetchPackage(ctx, name)
	if err != nil {
		return time.Time{}, err
	}
	if status == http.StatusNotFound {
		return time.Time{}, nil
	}
	if status != http.StatusOK || doc == nil {
		return time.Time{}, fmt.Errorf("npm publishedAtVersion %s@%s: HTTP %d", name, version, status)
	}
	ts, ok := doc.Time[version]
	if !ok {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return time.Time{}, fmt.Errorf("npm publishedAtVersion %s@%s: parse %q: %w", name, version, ts, err)
	}
	return t, nil
}

// PublisherOfVersion returns the npm-user account that published a
// given version. Used by the gate's publisher-change check: a
// version published by a different account than the prior trusted
// version is a takeover indicator.
//
// Returns ("", nil) when the registry response doesn't carry
// `_npmUser` (older publishes, registry mirrors). Callers should
// treat this as "unknown" rather than "no publisher" — the gate
// degrades to Verdict=Unknown in that case.
func (n *NPM) PublisherOfVersion(ctx context.Context, name, version string) (string, error) {
	status, doc, err := n.fetchPackage(ctx, name)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK || doc == nil {
		return "", nil
	}
	vm, ok := doc.Versions[version]
	if !ok {
		return "", nil
	}
	if vm.NPMUser != nil && vm.NPMUser.Name != "" {
		return vm.NPMUser.Name, nil
	}
	return "", nil
}

// VersionMetadata returns the per-version blob the gate needs for
// the static-pattern, install-script, and version-bump-diff
// checkers. Returns (nil, nil) when the version doesn't exist —
// callers should treat that as Unknown.
func (n *NPM) VersionMetadata(ctx context.Context, name, version string) (*VersionInfo, error) {
	status, doc, err := n.fetchPackage(ctx, name)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || doc == nil {
		return nil, nil
	}
	vm, ok := doc.Versions[version]
	if !ok {
		return nil, nil
	}
	publisher := ""
	if vm.NPMUser != nil {
		publisher = vm.NPMUser.Name
	}
	publishedAt := time.Time{}
	if ts, ok := doc.Time[version]; ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			publishedAt = t
		}
	}
	return &VersionInfo{
		Name:        vm.Name,
		Version:     vm.Version,
		Publisher:   publisher,
		PublishedAt: publishedAt,
		Scripts:     vm.Scripts,
	}, nil
}

// AllVersions returns the timeline of every published version
// (in chronological order by publish date) for a package.
// Used by the publisher-change check to find "the prior trusted
// version" given the version we're about to install.
func (n *NPM) AllVersions(ctx context.Context, name string) ([]VersionInfo, error) {
	status, doc, err := n.fetchPackage(ctx, name)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || doc == nil {
		return nil, nil
	}
	out := make([]VersionInfo, 0, len(doc.Versions))
	for ver, vm := range doc.Versions {
		publisher := ""
		if vm.NPMUser != nil {
			publisher = vm.NPMUser.Name
		}
		publishedAt := time.Time{}
		if ts, ok := doc.Time[ver]; ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				publishedAt = t
			}
		}
		out = append(out, VersionInfo{
			Name:        name,
			Version:     ver,
			Publisher:   publisher,
			PublishedAt: publishedAt,
			Scripts:     vm.Scripts,
		})
	}
	// Sort chronologically — oldest first, which is the order the
	// publisher-change check wants ("find the last version before X").
	sortVersionsByPublishedAt(out)
	return out, nil
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
