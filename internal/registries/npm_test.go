package registries

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestNPM(handler http.HandlerFunc) (*NPM, *httptest.Server) {
	srv := httptest.NewServer(handler)
	return &NPM{
		Client:       srv.Client(),
		RegistryURL:  srv.URL,
		DownloadsURL: srv.URL + "/downloads/point/last-week",
	}, srv
}

func TestNPMExists(t *testing.T) {
	n, srv := newTestNPM(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lodash":
			fmt.Fprint(w, `{"time":{"created":"2012-04-23T16:37:11.912Z"}}`)
		case "/%40scope/private":
			http.NotFound(w, r)
		case "/totally-broken":
			http.Error(w, "boom", 500)
		default:
			http.NotFound(w, r)
		}
	})
	defer srv.Close()
	ctx := context.Background()
	if ok, err := n.Exists(ctx, "lodash"); err != nil || !ok {
		t.Errorf("lodash should exist: ok=%v err=%v", ok, err)
	}
	if ok, err := n.Exists(ctx, "@scope/private"); err != nil || ok {
		t.Errorf("@scope/private should not exist: ok=%v err=%v", ok, err)
	}
	if _, err := n.Exists(ctx, "totally-broken"); err == nil {
		t.Errorf("expected error on HTTP 500")
	}
}

func TestNPMPublishedAt(t *testing.T) {
	n, srv := newTestNPM(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lodash" {
			fmt.Fprint(w, `{"time":{"created":"2012-04-23T16:37:11.912Z","1.0.0":"2012-05-01T00:00:00.000Z"}}`)
			return
		}
		http.NotFound(w, r)
	})
	defer srv.Close()
	t0, err := n.PublishedAt(context.Background(), "lodash")
	if err != nil {
		t.Fatal(err)
	}
	if t0.Year() != 2012 {
		t.Errorf("got %v, expected 2012", t0)
	}
	// 404 → zero time, no error.
	t1, err := n.PublishedAt(context.Background(), "does-not-exist")
	if err != nil || !t1.IsZero() {
		t.Errorf("404 should return zero+nil, got %v %v", t1, err)
	}
}

func TestNPMDownloadsLast7d(t *testing.T) {
	n, srv := newTestNPM(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/downloads/point/last-week/lodash":
			fmt.Fprint(w, `{"downloads":12345678,"package":"lodash"}`)
		case "/downloads/point/last-week/new-pkg":
			fmt.Fprint(w, `{"downloads":42}`)
		default:
			http.NotFound(w, r)
		}
	})
	defer srv.Close()
	n.DownloadsURL = srv.URL + "/downloads/point/last-week"
	if d, err := n.DownloadsLast7d(context.Background(), "lodash"); err != nil || d != 12345678 {
		t.Errorf("lodash downloads: got %d err=%v", d, err)
	}
	if d, err := n.DownloadsLast7d(context.Background(), "new-pkg"); err != nil || d != 42 {
		t.Errorf("new-pkg: got %d err=%v", d, err)
	}
	if d, err := n.DownloadsLast7d(context.Background(), "does-not-exist"); err != nil || d != 0 {
		t.Errorf("missing: got %d err=%v", d, err)
	}
}

func TestEncodeNPMName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"lodash", "lodash"},
		{"@scope/pkg", "@scope%2Fpkg"},
		{"@scope/pkg-with-dash", "@scope%2Fpkg-with-dash"},
	}
	for _, c := range cases {
		if got := encodeNPMName(c.in); got != c.want {
			t.Errorf("encodeNPMName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCachedAvoidsSecondRoundTrip(t *testing.T) {
	hits := 0
	n, srv := newTestNPM(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprint(w, `{"time":{"created":"2020-01-01T00:00:00.000Z"}}`)
	})
	defer srv.Close()
	n.DownloadsURL = srv.URL + "/downloads/point/last-week"
	tmp := t.TempDir() + "/cache.json"
	c := &Cached{Inner: n, Ecosystem: "npm", TTL: time.Hour, Path: tmp}
	if _, err := c.Exists(context.Background(), "lodash"); err != nil {
		t.Fatal(err)
	}
	firstHits := hits
	if _, err := c.PublishedAt(context.Background(), "lodash"); err != nil {
		t.Fatal(err)
	}
	if hits != firstHits {
		t.Errorf("second call should hit cache, but registry was called %d more times", hits-firstHits)
	}
}
