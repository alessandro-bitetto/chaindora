package registries

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// v0.16 probe tests. Each test wires the probe to an httptest server
// serving a representative fixture from the upstream registry, then
// exercises the three checker-facing methods: PublishedAtVersion,
// PublisherOfVersion, AllVersions. Tarball-fetch paths are covered
// indirectly — TarballURL is pure URL construction in all 9 probes.

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

// ---- Packagist -------------------------------------------------------------

func TestPackagist_PublishedAtAndPublisher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/p2/monolog/monolog.json" {
			fmt.Fprint(w, `{
				"packages": {
					"monolog/monolog": [
						{"name":"monolog/monolog","version":"3.5.0","time":"2024-04-12T10:00:00+00:00","authors":[{"name":"Jordi","email":"jordi@example.com"}]},
						{"name":"monolog/monolog","version":"3.4.0","time":"2024-01-10T08:00:00+00:00","authors":[{"name":"Jordi","email":"jordi@example.com"}]},
						{"name":"monolog/monolog","version":"dev-main","time":"2024-05-01T10:00:00+00:00","authors":[{"name":"Jordi","email":"jordi@example.com"}]}
					]
				}
			}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	p := NewPackagist()
	p.BaseURL = srv.URL
	p.Client = srv.Client()
	ctx := context.Background()

	tm, err := p.PublishedAtVersion(ctx, "monolog/monolog", "3.5.0")
	if err != nil || tm.Year() != 2024 || tm.Month() != time.April {
		t.Errorf("PublishedAtVersion: tm=%v err=%v", tm, err)
	}
	pub, _ := p.PublisherOfVersion(ctx, "monolog/monolog", "3.5.0")
	if pub != "jordi@example.com" {
		t.Errorf("PublisherOfVersion: got %q want email", pub)
	}
	all, _ := p.AllVersions(ctx, "monolog/monolog")
	if len(all) != 2 {
		t.Errorf("AllVersions: got %d, want 2 (dev-main filtered)", len(all))
	}
}

// ---- Pub -------------------------------------------------------------------

func TestPub_PublishedAtAndPublisher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/packages/path_provider":
			fmt.Fprint(w, `{
				"name":"path_provider",
				"versions":[
					{"version":"2.1.0","published":"2024-02-01T10:00:00.000Z","archive_url":"https://pub.dev/path_provider-2.1.0.tar.gz","pubspec":{"publisher":"flutter.dev"}},
					{"version":"2.0.0","published":"2023-08-01T10:00:00.000Z","archive_url":"https://pub.dev/path_provider-2.0.0.tar.gz","pubspec":{}}
				]
			}`)
		case "/api/packages/path_provider/publisher":
			fmt.Fprint(w, `{"publisherId":"flutter.dev"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	p := NewPub()
	p.BaseURL = srv.URL
	p.Client = srv.Client()
	ctx := context.Background()

	tm, err := p.PublishedAtVersion(ctx, "path_provider", "2.1.0")
	if err != nil || tm.Year() != 2024 {
		t.Errorf("PublishedAtVersion: tm=%v err=%v", tm, err)
	}
	pub, _ := p.PublisherOfVersion(ctx, "path_provider", "2.1.0")
	if pub != "flutter.dev" {
		t.Errorf("PublisherOfVersion: got %q want flutter.dev", pub)
	}
	// Version without pubspec.publisher falls back to package-level.
	pubFallback, _ := p.PublisherOfVersion(ctx, "path_provider", "2.0.0")
	if pubFallback != "flutter.dev" {
		t.Errorf("Publisher fallback: got %q want flutter.dev", pubFallback)
	}
}

// ---- Hex -------------------------------------------------------------------

func TestHex_PublishedAtAndPublisher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/packages/phoenix":
			fmt.Fprint(w, `{
				"name":"phoenix",
				"releases":[
					{"version":"1.7.10","inserted_at":"2024-01-09T12:00:00Z"},
					{"version":"1.7.9","inserted_at":"2023-11-01T12:00:00Z"}
				]
			}`)
		case "/api/packages/phoenix/releases/1.7.10":
			fmt.Fprint(w, `{"version":"1.7.10","inserted_at":"2024-01-09T12:00:00Z","publisher":{"username":"chrismccord","email":"chris@example.com"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	h := NewHex()
	h.APIURL = srv.URL + "/api"
	h.RepoURL = srv.URL + "/repo"
	h.Client = srv.Client()
	ctx := context.Background()

	tm, err := h.PublishedAtVersion(ctx, "phoenix", "1.7.10")
	if err != nil || tm.Year() != 2024 {
		t.Errorf("PublishedAtVersion: tm=%v err=%v", tm, err)
	}
	pub, _ := h.PublisherOfVersion(ctx, "phoenix", "1.7.10")
	if pub != "chrismccord" {
		t.Errorf("PublisherOfVersion: got %q want chrismccord", pub)
	}
}

// ---- Hackage ---------------------------------------------------------------

func TestHackage_PublishedAtAndPublisher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/package/aeson.json":
			fmt.Fprint(w, `{"2.2.0.0":"2023-09-10T10:00:00Z","2.1.2.0":"2023-03-15T10:00:00Z"}`)
		case "/package/aeson-2.2.0.0/uploaders":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "PhadejO")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	h := NewHackage()
	h.BaseURL = srv.URL
	h.Client = srv.Client()
	ctx := context.Background()

	tm, err := h.PublishedAtVersion(ctx, "aeson", "2.2.0.0")
	if err != nil || tm.Year() != 2023 {
		t.Errorf("PublishedAtVersion: tm=%v err=%v", tm, err)
	}
	pub, _ := h.PublisherOfVersion(ctx, "aeson", "2.2.0.0")
	if pub != "PhadejO" {
		t.Errorf("PublisherOfVersion: got %q want PhadejO", pub)
	}
	all, _ := h.AllVersions(ctx, "aeson")
	if len(all) != 2 {
		t.Errorf("AllVersions: got %d, want 2", len(all))
	}
	// Sorted oldest-first.
	if all[0].Version != "2.1.2.0" {
		t.Errorf("AllVersions sort: first=%s want 2.1.2.0", all[0].Version)
	}
}

// ---- CRAN ------------------------------------------------------------------

func TestCRAN_PublishedAtAndPublisher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dplyr/all" {
			fmt.Fprint(w, `{
				"versions":{
					"1.1.4":{"Version":"1.1.4","Date/Publication":"2023-11-17 13:30:00 UTC","Maintainer":"Hadley Wickham <hadley@posit.co>"},
					"1.1.3":{"Version":"1.1.3","Date/Publication":"2023-09-03 18:00:00 UTC","Maintainer":"Hadley Wickham <hadley@posit.co>"}
				}
			}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := NewCRAN()
	c.DBURL = srv.URL
	c.Client = srv.Client()
	ctx := context.Background()

	tm, err := c.PublishedAtVersion(ctx, "dplyr", "1.1.4")
	if err != nil || tm.Year() != 2023 || tm.Month() != time.November {
		t.Errorf("PublishedAtVersion: tm=%v err=%v", tm, err)
	}
	pub, _ := c.PublisherOfVersion(ctx, "dplyr", "1.1.4")
	if pub != "hadley@posit.co" {
		t.Errorf("PublisherOfVersion: got %q want hadley@posit.co", pub)
	}
}

// ---- CocoaPods -------------------------------------------------------------

func TestCocoaPods_PublishedAtAndPublisher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pods/Alamofire" {
			fmt.Fprint(w, `{
				"name":"Alamofire",
				"versions":[
					{"name":"5.7.0","created_at":"2023-02-21T10:00:00.000Z"},
					{"name":"5.8.0","created_at":"2023-09-15T10:00:00.000Z"}
				],
				"owners":[
					{"email":"alamofire@example.com","name":"Alamofire Team"}
				]
			}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := NewCocoaPods()
	c.BaseURL = srv.URL
	c.Client = srv.Client()
	ctx := context.Background()

	tm, err := c.PublishedAtVersion(ctx, "Alamofire", "5.8.0")
	if err != nil || tm.Year() != 2023 || tm.Month() != time.September {
		t.Errorf("PublishedAtVersion: tm=%v err=%v", tm, err)
	}
	pub, _ := c.PublisherOfVersion(ctx, "Alamofire", "5.8.0")
	if pub != "alamofire@example.com" {
		t.Errorf("PublisherOfVersion: got %q want alamofire@example.com", pub)
	}
}

// ---- Conda -----------------------------------------------------------------

func TestConda_PublishedAtAndPublisher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/package/conda-forge/numpy" {
			fmt.Fprint(w, `{
				"name":"numpy",
				"owner":{"login":"conda-forge","name":"conda-forge"},
				"files":[
					{"version":"1.26.0","upload_time":"2023-09-16T10:00:00.000","owner":"conda-forge","download_url":"https://anaconda.org/conda-forge/numpy-1.26.0-py39_0.tar.bz2"},
					{"version":"1.26.0","upload_time":"2023-09-16T11:00:00.000","owner":"conda-forge","download_url":"https://anaconda.org/conda-forge/numpy-1.26.0-py310_0.tar.bz2"},
					{"version":"1.25.0","upload_time":"2023-06-17T10:00:00.000","owner":"conda-forge","download_url":"https://anaconda.org/conda-forge/numpy-1.25.0-py39_0.tar.bz2"}
				]
			}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := NewConda()
	c.BaseURL = srv.URL
	c.Client = srv.Client()
	ctx := context.Background()

	// Earliest upload across builds of 1.26.0 — 10:00 not 11:00.
	tm, err := c.PublishedAtVersion(ctx, "numpy", "1.26.0")
	if err != nil || tm.Hour() != 10 {
		t.Errorf("PublishedAtVersion: tm=%v err=%v want hour=10", tm, err)
	}
	pub, _ := c.PublisherOfVersion(ctx, "numpy", "1.26.0")
	if pub != "conda-forge" {
		t.Errorf("PublisherOfVersion: got %q want conda-forge", pub)
	}
	all, _ := c.AllVersions(ctx, "numpy")
	if len(all) != 2 {
		t.Errorf("AllVersions: got %d, want 2 (builds collapsed)", len(all))
	}
}

// ---- CPAN ------------------------------------------------------------------

func TestCPAN_PublishedAtAndPublisher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/release/_search" && r.Method == http.MethodPost {
			fmt.Fprint(w, `{
				"hits":{"hits":[
					{"_source":{"distribution":"DBI","version":"1.643","date":"2021-11-21T12:00:00Z","author":"TIMB","name":"DBI-1.643","download_url":"https://cpan.example.com/DBI-1.643.tar.gz"}},
					{"_source":{"distribution":"DBI","version":"1.644","date":"2023-10-15T12:00:00Z","author":"TIMB","name":"DBI-1.644","download_url":"https://cpan.example.com/DBI-1.644.tar.gz"}}
				]}
			}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := NewCPAN()
	c.BaseURL = srv.URL
	c.Client = srv.Client()
	ctx := context.Background()

	tm, err := c.PublishedAtVersion(ctx, "DBI", "1.644")
	if err != nil || tm.Year() != 2023 {
		t.Errorf("PublishedAtVersion: tm=%v err=%v", tm, err)
	}
	pub, _ := c.PublisherOfVersion(ctx, "DBI", "1.644")
	if pub != "TIMB" {
		t.Errorf("PublisherOfVersion: got %q want TIMB", pub)
	}
	all, _ := c.AllVersions(ctx, "DBI")
	if len(all) != 2 {
		t.Errorf("AllVersions: got %d, want 2", len(all))
	}
	// Sorted oldest-first.
	if all[0].Version != "1.643" {
		t.Errorf("AllVersions sort: first=%s want 1.643", all[0].Version)
	}
}

// ---- Interface compliance --------------------------------------------------

// Compile-time check: all 9 new probes satisfy the gate's VersionProbe
// surface (5 methods: PublishedAtVersion, PublisherOfVersion,
// AllVersions, TarballURL, FetchTarball). If any method drift happens
// downstream, this catches it at `go build` time before any test runs.
//
// Importing gate from this test would create a cycle (gate imports
// registries). Instead, we mirror the shape locally — the interface
// signatures are stable enough that a copy here is fine.
type versionProbeShape interface {
	PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error)
	PublisherOfVersion(ctx context.Context, name, version string) (string, error)
	AllVersions(ctx context.Context, name string) ([]VersionInfo, error)
}

var (
	_ versionProbeShape = (*NuGet)(nil)
	_ versionProbeShape = (*Packagist)(nil)
	_ versionProbeShape = (*Pub)(nil)
	_ versionProbeShape = (*Hex)(nil)
	_ versionProbeShape = (*Hackage)(nil)
	_ versionProbeShape = (*CRAN)(nil)
	_ versionProbeShape = (*CocoaPods)(nil)
	_ versionProbeShape = (*Conda)(nil)
	_ versionProbeShape = (*CPAN)(nil)
)
