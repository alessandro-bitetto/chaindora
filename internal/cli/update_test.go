package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateIncidentYAML(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"valid", "schema: 1\nid: TEST-1\nname: x\n", true},
		{"missing id", "schema: 1\nname: x\n", false},
		{"empty id", "schema: 1\nid: \"\"\nname: x\n", false},
		{"malformed yaml", "schema: 1\nid: TEST-1\n  bad-indent: oops\n - !!!", false},
		{"empty body", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := validateIncidentYAML([]byte(c.body)); got != c.want {
				t.Errorf("validateIncidentYAML(%q) = %v, want %v", c.body, got, c.want)
			}
		})
	}
}

func TestUpdateHappyPath(t *testing.T) {
	dest := t.TempDir()

	srv := newMockUpstream(t, map[string]string{
		"alpha.yaml": "schema: 1\nid: ALPHA-1\nname: alpha incident\n",
		"beta.yaml":  "schema: 1\nid: BETA-1\nname: beta incident\n",
	})
	defer srv.Close()

	// Reset flags to defaults for this test
	updateSource = srv.URL + "/list"
	updateDest = dest
	updateDryRun = false
	updateVerbose = false

	if err := runUpdate(nil, nil); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"alpha.yaml", "beta.yaml"} {
		if _, err := os.Stat(filepath.Join(dest, name)); err != nil {
			t.Errorf("expected %s to be written: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, ".meta.json")); err != nil {
		t.Errorf("expected .meta.json to be written: %v", err)
	}
}

func TestUpdateRejectsMalformedYAML(t *testing.T) {
	dest := t.TempDir()
	srv := newMockUpstream(t, map[string]string{
		"good.yaml": "schema: 1\nid: GOOD-1\n",
		"bad.yaml":  "this is not :: valid: yaml: at: all : ! ! !",
	})
	defer srv.Close()

	updateSource = srv.URL + "/list"
	updateDest = dest
	updateDryRun = false

	if err := runUpdate(nil, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dest, "good.yaml")); err != nil {
		t.Errorf("good.yaml should be written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "bad.yaml")); !os.IsNotExist(err) {
		t.Errorf("bad.yaml should NOT be written; got err = %v", err)
	}
}

func TestUpdateDryRunDoesNotWrite(t *testing.T) {
	dest := t.TempDir()
	srv := newMockUpstream(t, map[string]string{"x.yaml": "schema: 1\nid: X-1\n"})
	defer srv.Close()

	updateSource = srv.URL + "/list"
	updateDest = dest
	updateDryRun = true

	if err := runUpdate(nil, nil); err != nil {
		t.Fatal(err)
	}

	entries, _ := os.ReadDir(dest)
	if len(entries) != 0 {
		t.Errorf("dry-run wrote files: %v", entries)
	}
}

func TestUpdateUnchangedDedup(t *testing.T) {
	dest := t.TempDir()
	body := "schema: 1\nid: STABLE-1\nname: stable\n"
	if err := os.WriteFile(filepath.Join(dest, "stable.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	originalInfo, _ := os.Stat(filepath.Join(dest, "stable.yaml"))

	srv := newMockUpstream(t, map[string]string{"stable.yaml": body})
	defer srv.Close()

	updateSource = srv.URL + "/list"
	updateDest = dest
	updateDryRun = false

	if err := runUpdate(nil, nil); err != nil {
		t.Fatal(err)
	}
	newInfo, _ := os.Stat(filepath.Join(dest, "stable.yaml"))
	if !newInfo.ModTime().Equal(originalInfo.ModTime()) {
		t.Errorf("unchanged file got rewritten (mtime moved %v → %v)", originalInfo.ModTime(), newInfo.ModTime())
	}
}

// newMockUpstream returns an httptest.Server that mimics the GitHub Contents
// API: /list returns the JSON file-entry array; each entry's DownloadURL
// points back at the same server's /raw/<name> endpoint.
func newMockUpstream(t *testing.T, files map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		entries := make([]githubContentEntry, 0, len(files))
		for name := range files {
			entries = append(entries, githubContentEntry{
				Name:        name,
				Path:        "incidents/" + name,
				Type:        "file",
				DownloadURL: srv.URL + "/raw/" + name,
			})
		}
		_ = json.NewEncoder(w).Encode(entries)
	})
	mux.HandleFunc("/raw/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/raw/")
		body, ok := files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	})
	return srv
}
