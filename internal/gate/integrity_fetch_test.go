package gate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// canned is a tiny RoundTripper for integrityHTTPClient stub-out. We
// swap the package-level integrityHTTPClient's Transport for one of
// these in each test, then restore afterward.
type canned struct {
	responses map[string]cannedResp // keyed on URL prefix substring
	misses    int
}

type cannedResp struct {
	status int
	body   string
}

func (c *canned) RoundTrip(req *http.Request) (*http.Response, error) {
	url := req.URL.String()
	for prefix, resp := range c.responses {
		if strings.Contains(url, prefix) {
			return &http.Response{
				StatusCode: resp.status,
				Body:       httptest.NewRecorder().Result().Body,
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
		_ = resp
	}
	c.misses++
	return &http.Response{StatusCode: 404, Body: http.NoBody, Header: make(http.Header), Request: req}, nil
}

// swapHTTPClient swaps the integrityHTTPClient for the test's duration
// and restores it on cleanup. Uses a real httptest.Server so the body
// is wired correctly (the canned RoundTripper above is too crude for
// JSON-body responses).
func swapHTTPClient(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	prev := integrityHTTPClient
	integrityHTTPClient = srv.Client()
	t.Cleanup(func() { integrityHTTPClient = prev })
	return srv
}

func TestEnrichRubyGemsIntegrity_SkipsNonRubyGemsEcosystem(t *testing.T) {
	refs := []PackageRef{
		{Ecosystem: "npm", Name: "lodash", Version: "1.0.0"},
		{Ecosystem: "pypi", Name: "requests", Version: "2.0.0"},
	}
	got := EnrichRubyGemsIntegrity(context.Background(), refs)
	for _, r := range got {
		if r.Integrity != "" {
			t.Errorf("non-rubygems ref got integrity stuffed: %+v", r)
		}
	}
}

func TestEnrichRubyGemsIntegrity_SkipsAlreadyPopulated(t *testing.T) {
	refs := []PackageRef{
		{Ecosystem: "rubygems", Name: "rails", Version: "7.0.0", Integrity: "sha256:KEEP"},
	}
	got := EnrichRubyGemsIntegrity(context.Background(), refs)
	if got[0].Integrity != "sha256:KEEP" {
		t.Errorf("pre-populated integrity must be preserved, got %q", got[0].Integrity)
	}
}

func TestEnrichMavenIntegrity_SkipsNonMavenEcosystem(t *testing.T) {
	refs := []PackageRef{
		{Ecosystem: "npm", Name: "lodash", Version: "1.0.0"},
	}
	got := EnrichMavenIntegrity(context.Background(), refs)
	if got[0].Integrity != "" {
		t.Errorf("non-maven ref got integrity stuffed: %+v", got[0])
	}
}

func TestFetchMavenSHA_RejectsBadFullName(t *testing.T) {
	// No colon → can't split into group/artifact.
	if got := fetchMavenSHA(context.Background(), "no-colon", "1.0.0"); got != "" {
		t.Errorf("expected empty on bad name, got %q", got)
	}
	// Colon at position 0 → empty group.
	if got := fetchMavenSHA(context.Background(), ":artifact", "1.0.0"); got != "" {
		t.Errorf("expected empty on empty-group, got %q", got)
	}
	// Colon at end → empty artifact.
	if got := fetchMavenSHA(context.Background(), "group:", "1.0.0"); got != "" {
		t.Errorf("expected empty on empty-artifact, got %q", got)
	}
}

func TestFetchMavenHashBody_NonHexBodyRejected(t *testing.T) {
	// A server returning an HTML error page (wrong Content-Type) must
	// not pass — the function validates that the body is hex.
	srv := swapHTTPClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html>not a hash</html>"))
	}))
	if got := fetchMavenHashBody(context.Background(), srv.URL+"/anything"); got != "" {
		t.Errorf("non-hex body must yield empty, got %q", got)
	}
}

func TestFetchMavenHashBody_404Returns(t *testing.T) {
	srv := swapHTTPClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	if got := fetchMavenHashBody(context.Background(), srv.URL+"/missing"); got != "" {
		t.Errorf("404 must yield empty, got %q", got)
	}
}

func TestFetchMavenHashBody_AcceptsHexWithTrailingFilename(t *testing.T) {
	// Maven .sha1 files sometimes look like "ABC...  artifact.jar"
	// — the function must strip whitespace and return just the hex.
	hash := "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	srv := swapHTTPClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(hash + "  artifact-1.0.jar"))
	}))
	if got := fetchMavenHashBody(context.Background(), srv.URL+"/x"); got != hash {
		t.Errorf("got %q, want %q", got, hash)
	}
}
