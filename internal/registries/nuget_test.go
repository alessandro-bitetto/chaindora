package registries

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// NuGet probe tests use an HTTP fixture; no live registry calls.

// ---- NuGet -----------------------------------------------------------------

func TestNuGet_PublishedAtAndPublisher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/index.json"):
			fmt.Fprint(w, `{"versions":["4.0.1","4.0.2"]}`)
		case strings.HasSuffix(r.URL.Path, "/4.0.2.json"):
			fmt.Fprint(w, `{"catalogEntry":{"id":"AWSSDK.S3","version":"4.0.2","published":"2024-12-01T10:00:00Z","authors":"Amazon Web Services, Inc., Other"}}`)
		case strings.HasSuffix(r.URL.Path, "/1.0.0.json"):
			// Sentinel unlisted-package date.
			fmt.Fprint(w, `{"catalogEntry":{"id":"Old","version":"1.0.0","published":"1900-01-01T00:00:00Z","authors":"Anon"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	n := NewNuGet()
	n.BaseURL = srv.URL
	n.Client = srv.Client()
	ctx := context.Background()

	tm, err := n.PublishedAtVersion(ctx, "AWSSDK.S3", "4.0.2")
	if err != nil || tm.Year() != 2024 {
		t.Errorf("PublishedAtVersion: tm=%v err=%v", tm, err)
	}
	tm2, _ := n.PublishedAtVersion(ctx, "AWSSDK.S3", "1.0.0")
	if !tm2.IsZero() {
		t.Errorf("unlisted-sentinel date should be zero, got %v", tm2)
	}
	pub, _ := n.PublisherOfVersion(ctx, "AWSSDK.S3", "4.0.2")
	if pub != "Amazon Web Services" {
		t.Errorf("PublisherOfVersion: got %q want first authors entry", pub)
	}
	all, _ := n.AllVersions(ctx, "AWSSDK.S3")
	if len(all) != 2 {
		t.Errorf("AllVersions: got %d, want 2", len(all))
	}
}
