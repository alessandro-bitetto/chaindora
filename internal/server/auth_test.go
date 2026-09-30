package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestFleetReadsRequireIndependentOperatorCredential(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(store, "enrollment-secret", "test")
	s.ReadToken = "operator-token"
	for _, path := range []string{"/", "/api/v1/agents", "/api/v1/agents/example", "/api/v1/findings", "/api/v1/summary"} {
		for _, token := range []string{"", "wrong", "enrollment-secret", "operator-token"} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", path, nil)
			if token != "" {
				r.Header.Set("Authorization", "Bearer "+token)
			}
			s.Handler().ServeHTTP(w, r)
			if token == "operator-token" {
				if w.Code != 200 && w.Code != 404 {
					t.Fatalf("authorized %s: %d", path, w.Code)
				}
			} else if w.Code != 401 {
				t.Fatalf("unauthorized %s: %d", path, w.Code)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("sensitive response cacheable")
			}
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/summary", nil)
	r.SetBasicAuth("viewer", s.ReadToken)
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("browser auth rejected")
	}
	s.ReadToken = ""
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal("unconfigured auth failed open")
	}
}

func TestEnrollmentDisabledWithoutSecret(t *testing.T) {
	store, _ := NewStore(filepath.Join(t.TempDir(), "state.json"))
	s := New(store, "", "test")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/agents/enroll", strings.NewReader(`{"name":"example"}`)))
	if w.Code != 503 || len(store.ListAgents()) != 0 {
		t.Fatal("unauthenticated agent enrolled")
	}
}
