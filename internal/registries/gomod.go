package registries

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GoMod probes the Go module proxy at proxy.golang.org. The
// proxy implements GOPROXY semantics:
//
//   GET /<module>/@v/list              → newline-separated versions
//   GET /<module>/@v/<version>.info    → JSON{Version,Time}
//   GET /<module>/@v/<version>.zip     → module source (zip)
//
// Per-version publisher metadata isn't exposed (Go modules don't
// have a "publisher" concept — the trust unit is the
// module-path host, often GitHub). PublisherOfVersion returns ""
// and publisher-change degrades to Unknown, matching Maven's
// pattern.
//
// Sumdb verification (sum.golang.org) is out of scope for v0.11.2
// but is the natural place for v0.11.3+ — go.sum entries can be
// cross-checked against the sumdb to detect MITM-replaced modules.
type GoMod struct {
	Client    *http.Client
	BaseURL   string // default: https://proxy.golang.org
	UserAgent string

	// list caches @v/list responses since hitting it for every
	// AllVersions call would be wasteful (Go modules can have
	// hundreds of versions).
	listMu sync.Mutex
	list   map[string][]string
}

func NewGoMod() *GoMod {
	return &GoMod{
		Client:    &http.Client{Timeout: 10 * time.Second},
		BaseURL:   "https://proxy.golang.org",
		UserAgent: "chdora-registry/",
		list:      map[string][]string{},
	}
}

// goModEscape applies the GOPROXY module-path escaping: every
// uppercase letter becomes `!` + lowercase. `proxy.golang.org`
// requires this for case-insensitive filesystem compatibility.
func goModEscape(module string) string {
	var b strings.Builder
	for _, r := range module {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (g *GoMod) fetchList(ctx context.Context, module string) ([]string, error) {
	g.listMu.Lock()
	cached, ok := g.list[module]
	g.listMu.Unlock()
	if ok {
		return cached, nil
	}
	url := strings.TrimRight(g.BaseURL, "/") + "/" + goModEscape(module) + "/@v/list"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if g.UserAgent != "" {
		req.Header.Set("User-Agent", g.UserAgent)
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gomod list %s: HTTP %d", module, resp.StatusCode)
	}
	var versions []string
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 4<<20))
	for sc.Scan() {
		v := strings.TrimSpace(sc.Text())
		if v != "" {
			versions = append(versions, v)
		}
	}
	g.listMu.Lock()
	g.list[module] = versions
	g.listMu.Unlock()
	return versions, nil
}

type goModInfoDoc struct {
	Version string `json:"Version"`
	Time    string `json:"Time"`
}

func (g *GoMod) fetchInfo(ctx context.Context, module, version string) (*goModInfoDoc, error) {
	url := fmt.Sprintf("%s/%s/@v/%s.info",
		strings.TrimRight(g.BaseURL, "/"),
		goModEscape(module), version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if g.UserAgent != "" {
		req.Header.Set("User-Agent", g.UserAgent)
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gomod info %s@%s: HTTP %d", module, version, resp.StatusCode)
	}
	var doc goModInfoDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func (g *GoMod) PublishedAtVersion(ctx context.Context, module, version string) (time.Time, error) {
	info, err := g.fetchInfo(ctx, module, version)
	if err != nil || info == nil {
		return time.Time{}, err
	}
	t, _ := time.Parse(time.RFC3339Nano, info.Time)
	if t.IsZero() {
		t, _ = time.Parse(time.RFC3339, info.Time)
	}
	return t, nil
}

// PublisherOfVersion uses the module path itself as the
// publisher identity. Go modules have no proxy-level publisher
// field, but the module path IS the trust unit:
// `github.com/spf13/cobra` is owned by github.com user/org
// `spf13`. If the module path changes between versions (rare —
// usually only on major bumps with `/vN` suffix), that's a
// migration signal. If we can't extract an owner from the
// module path (bare `golang.org/x/...` style), return "" so
// publisher-change degrades to Unknown.
func (g *GoMod) PublisherOfVersion(_ context.Context, module, _ string) (string, error) {
	return ModuleOwner(module), nil
}

// ModuleOwner extracts the publisher identity from a Go module
// path. Three tiers:
//   1. github/gitlab/bitbucket/codeberg → `<host>/<owner>`
//      ("github.com/spf13"). Cross-version comparison catches
//      a takeover that moved the module to a different owner.
//   2. Vanity hosts (gopkg.in, golang.org/x, go.uber.org, ...)
//      → the first path segment ("gopkg.in"). Comparing across
//      versions of the same module yields Approve since the
//      module path is invariant — the alternative is
//      fail-closed Unknown on every vanity import, which would
//      block every Go gate run on a real codebase.
func ModuleOwner(module string) string {
	for _, host := range []string{"github.com/", "gitlab.com/", "bitbucket.org/", "codeberg.org/"} {
		if strings.HasPrefix(module, host) {
			rest := strings.TrimPrefix(module, host)
			if i := strings.Index(rest, "/"); i > 0 {
				return strings.TrimSuffix(host, "/") + "/" + rest[:i]
			}
			return strings.TrimSuffix(host, "/")
		}
	}
	// Vanity-path fallback: use the host (first path segment).
	// For "gopkg.in/check.v1" returns "gopkg.in"; for
	// "go.uber.org/zap" returns "go.uber.org". The publisher-
	// change check then resolves to Approve when the host is
	// the same across versions — the host IS the trust unit
	// for vanity imports.
	if i := strings.Index(module, "/"); i > 0 {
		return module[:i]
	}
	return module
}

// AllVersions iterates @v/list and fetches .info for each.
// Caps at the most-recent 30 versions to bound HTTP traffic
// for modules with deep histories (e.g. golang.org/x/sys has
// hundreds of pseudo-versions).
func (g *GoMod) AllVersions(ctx context.Context, module string) ([]VersionInfo, error) {
	versions, err := g.fetchList(ctx, module)
	if err != nil {
		return nil, err
	}
	const cap = 30
	if len(versions) > cap {
		versions = versions[len(versions)-cap:]
	}
	owner := ModuleOwner(module)
	out := make([]VersionInfo, 0, len(versions))
	for _, v := range versions {
		info, err := g.fetchInfo(ctx, module, v)
		if err != nil || info == nil {
			continue
		}
		t, _ := time.Parse(time.RFC3339Nano, info.Time)
		if t.IsZero() {
			t, _ = time.Parse(time.RFC3339, info.Time)
		}
		out = append(out, VersionInfo{
			Name:        module,
			Version:     v,
			Publisher:   owner,
			PublishedAt: t,
		})
	}
	sortVersionsByPublishedAt(out)
	return out, nil
}

// TarballURL returns the module-zip download URL.
func (g *GoMod) TarballURL(_ context.Context, module, version string) (string, error) {
	return fmt.Sprintf("%s/%s/@v/%s.zip",
		strings.TrimRight(g.BaseURL, "/"),
		goModEscape(module), version,
	), nil
}

// SumDBLookupURL is sum.golang.org's canonical endpoint. Override
// in tests with httptest.Server addresses.
const SumDBLookupURL = "https://sum.golang.org/lookup"

// HasProvenance reports whether sum.golang.org has a signed
// note for (module, version). Go's sumdb is Go-team-signed
// cryptographic attestation — every indexed module version
// gets one. A 200 response means the module is in the
// transparency log; the Go build system already enforces this
// for `go.sum`-pinned modules. We surface it as the Go
// equivalent of npm sigstore provenance.
//
// Lookups against sumdb are HEAD-friendly but the endpoint
// doesn't reliably accept HEAD across implementations, so we
// GET and discard the body.
func (g *GoMod) HasProvenance(ctx context.Context, module, version string) (bool, error) {
	url := fmt.Sprintf("%s/%s@%s",
		strings.TrimRight(SumDBLookupURL, "/"),
		goModEscape(module), version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	if g.UserAgent != "" {
		req.Header.Set("User-Agent", g.UserAgent)
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<14))
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound, http.StatusGone:
		return false, nil
	}
	return false, fmt.Errorf("sumdb lookup %s: HTTP %d", url, resp.StatusCode)
}

// AnyVersionHasProvenance returns true if ANY version of the
// module is sumdb-indexed. For Go modules in the public proxy,
// this is almost always true — sumdb indexes every module
// proxy.golang.org serves. The signal becomes useful when a
// proxy bypass (GOPROXY=direct, GOSUMDB=off) is configured;
// then absence-of-sumdb-entry is the regression case.
func (g *GoMod) AnyVersionHasProvenance(ctx context.Context, module string) (bool, error) {
	versions, err := g.fetchList(ctx, module)
	if err != nil || len(versions) == 0 {
		return false, err
	}
	// Check the most recent version — cheap and representative.
	return g.HasProvenance(ctx, module, versions[len(versions)-1])
}

func (g *GoMod) FetchTarball(ctx context.Context, fetchURL string, dst io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return err
	}
	if g.UserAgent != "" {
		req.Header.Set("User-Agent", g.UserAgent)
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gomod zip %s: HTTP %d", fetchURL, resp.StatusCode)
	}
	_, err = io.Copy(dst, io.LimitReader(resp.Body, 50<<20))
	return err
}
