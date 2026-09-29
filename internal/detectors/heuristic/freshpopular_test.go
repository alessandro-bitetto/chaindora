package heuristic

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

func TestDetectFreshPopularDisabledByDefault(t *testing.T) {
	inv := &inventory.Inventory{
		Packages: []inventory.Package{{Ecosystem: inventory.EcosystemNPM, Name: "lodash", Version: "4.17.21"}},
	}
	if got := detectFreshPopular(inv, FreshPopularConfig{}); len(got) != 0 {
		t.Errorf("disabled detector should emit nothing, got %+v", got)
	}
}

func TestDetectFreshPopularNPMFresh(t *testing.T) {
	freshTime := "2026-05-10T12:00:00.000Z"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/lodash") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"time": map[string]string{
					"4.17.21": freshTime,
					"4.17.20": "2020-08-13T15:00:00.000Z",
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	inv := &inventory.Inventory{
		Packages: []inventory.Package{
			{Ecosystem: inventory.EcosystemNPM, Name: "lodash", Version: "4.17.21"},
			{Ecosystem: inventory.EcosystemNPM, Name: "lodash", Version: "4.17.20"},   // old, should NOT fire
			{Ecosystem: inventory.EcosystemNPM, Name: "unknown-pkg", Version: "1.0"}, // not in top-N
		},
	}
	now := func() time.Time { t, _ := time.Parse(time.RFC3339, "2026-05-15T00:00:00Z"); return t }
	cfg := FreshPopularConfig{Enabled: true, NPMRegistryURL: srv.URL, Now: now}
	got := detectFreshPopular(inv, cfg)
	if len(got) != 1 {
		t.Fatalf("expected 1 fresh-popular finding, got %d: %+v", len(got), got)
	}
	if got[0].Name != "lodash" || got[0].Version != "4.17.21" {
		t.Errorf("wrong finding: %+v", got[0])
	}
}

func TestDetectFreshPopularPyPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"urls": []map[string]string{{"upload_time": "2026-05-12T08:00:00"}},
		})
	}))
	defer srv.Close()

	inv := &inventory.Inventory{
		Packages: []inventory.Package{{Ecosystem: inventory.EcosystemPyPI, Name: "requests", Version: "9.9.9"}},
	}
	now := func() time.Time { t, _ := time.Parse(time.RFC3339, "2026-05-15T00:00:00Z"); return t }
	cfg := FreshPopularConfig{Enabled: true, PyPIRegistryURL: srv.URL, Now: now}
	got := detectFreshPopular(inv, cfg)
	if len(got) != 1 {
		t.Fatalf("expected 1 PyPI fresh-popular finding, got %d", len(got))
	}
}

func TestDetectFreshPopularSkipsOnNetworkError(t *testing.T) {
	cfg := FreshPopularConfig{
		Enabled:        true,
		NPMRegistryURL: "http://127.0.0.1:1", // unreachable
		Now:            time.Now,
		HTTPClient:     &http.Client{Timeout: 100 * time.Millisecond},
	}
	inv := &inventory.Inventory{
		Packages: []inventory.Package{{Ecosystem: inventory.EcosystemNPM, Name: "lodash", Version: "4.17.21"}},
	}
	if got := detectFreshPopular(inv, cfg); len(got) != 0 {
		t.Errorf("expected zero findings on network error, got %+v (errors should be silently ignored — %s)", got, fmt.Sprintf("%v", got))
	}
}
