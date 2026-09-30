package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/artifacts"
)

type transactionTransport func(*http.Request) (*http.Response, error)

func (f transactionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func transactionFixture(t *testing.T) (string, []byte, *http.Client) {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("frozen transactions require macOS/Linux")
	}
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	archive := buildTarball(t, map[string]string{
		"package.json": `{"name":"fixture","version":"1.0.0","scripts":{"postinstall":"node sentinel.js"}}`,
		"index.js":     "module.exports=1;",
		"sentinel.js":  `require('fs').writeFileSync('lifecycle-ran', 'harmless test marker');`,
	})
	manifest := `{"name":"test-project","version":"1.0.0","dependencies":{"fixture":"1.0.0"}}`
	lock := map[string]any{"name": "test-project", "version": "1.0.0", "lockfileVersion": 3, "requires": true, "packages": map[string]any{
		"":                     map[string]any{"name": "test-project", "version": "1.0.0", "dependencies": map[string]string{"fixture": "1.0.0"}},
		"node_modules/fixture": map[string]any{"version": "1.0.0", "resolved": "https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz", "integrity": artifacts.SHA512(archive), "hasInstallScript": true},
	}}
	lockBytes, _ := json.Marshal(lock)
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), lockBytes, 0600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transactionTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(archive)), Header: make(http.Header)}, nil
	})}
	return root, archive, client
}

func TestNPMPrepareDoesNotExecutePackageManager(t *testing.T) {
	root, _, client := transactionFixture(t)
	tx, err := PrepareNPMTransaction(context.Background(), "/does-not-exist", root, []string{"ci"}, client, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	}()
	if len(tx.Refs) != 1 || tx.Refs[0].ArtifactPath == "" {
		t.Fatal("missing frozen artifact")
	}
	if _, err := os.Stat(filepath.Join(root, "node_modules")); !os.IsNotExist(err) {
		t.Fatal("preparation installed packages")
	}
}

func TestNPMTransactionRejectsChangesBeforeExecution(t *testing.T) {
	for _, change := range []string{"lock", "manifest", "artifact"} {
		t.Run(change, func(t *testing.T) {
			root, _, client := transactionFixture(t)
			tx, err := PrepareNPMTransaction(context.Background(), "/must-not-run", root, []string{"install"}, client, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := tx.Close(); err != nil {
					t.Error(err)
				}
			}()
			switch change {
			case "lock":
				if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "manifest":
				if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "artifact":
				if err := os.WriteFile(tx.Refs[0].ArtifactPath, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err = tx.Install(context.Background())
			if err == nil {
				t.Fatal("modified input accepted")
			}
			if strings.Contains(err.Error(), "must-not-run") {
				t.Fatalf("executed before rejecting modified %s: %v", change, err)
			}
		})
	}
}

func TestNPMTransactionRejectsSourcesAndOverrides(t *testing.T) {
	for _, args := range [][]string{{"install", "fixture"}, {"ci", "--ignore-scripts=false"}, {"--prefix=/tmp", "ci"}, {"update"}, {"ci", "--userconfig=other"}, {"ci", "--registry=https://other"}, {"ci", "--dry-run"}} {
		if ValidateNPMRestoreArgs(args) == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	for _, key := range []string{"../outside", "node_modules/../../outside", "node_modules/.bin/tool", "node_modules/a/extra", "/node_modules/a", "node_modules/a\\b"} {
		if validNPMInstallPath(key) {
			t.Errorf("accepted unsafe path %q", key)
		}
	}
	for _, key := range []string{"node_modules/a", "node_modules/@scope/pkg", "node_modules/a/node_modules/@scope/pkg"} {
		if !validNPMInstallPath(key) {
			t.Errorf("rejected path %q", key)
		}
	}
	for _, url := range []string{"http://registry.npmjs.org/a", "https://localhost/a", "https://registry.npmjs.org.evil/a", "https://token@registry.npmjs.org/a"} {
		if artifacts.NPMURL(url) == nil {
			t.Errorf("accepted source %s", url)
		}
	}
}

func TestNPMFrozenInstallRealOffline(t *testing.T) {
	npm := os.Getenv("CHAINDORA_TEST_NPM")
	if npm == "" {
		t.Skip("set CHAINDORA_TEST_NPM to a trusted real npm executable for the offline integration contract")
	}
	root, _, client := transactionFixture(t)
	tx, err := PrepareNPMTransaction(context.Background(), npm, root, []string{"ci"}, client, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	}()
	// An existing install survives all preparation and is replaced only after
	// verified, script-disabled staging succeeds.
	if err := os.MkdirAll(filepath.Join(root, "node_modules"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "old-marker"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := tx.Install(context.Background()); err != nil {
		if pe, ok := err.(*PMError); ok {
			t.Fatalf("%v: %s", err, pe.Output)
		}
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "node_modules", "fixture", "index.js")); err != nil || string(data) != "module.exports=1;" {
		t.Fatalf("wrong installed bytes: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(root, "node_modules", "fixture", "lifecycle-ran")); !os.IsNotExist(err) {
		t.Fatal("lifecycle hook executed")
	}
	if _, err := os.Stat(filepath.Join(root, "node_modules", "old-marker")); !os.IsNotExist(err) {
		t.Fatal("old install not replaced")
	}
}

func TestNPMFrozenInstallAliasTransitiveRealOffline(t *testing.T) {
	npm := os.Getenv("CHAINDORA_TEST_NPM")
	if npm == "" {
		t.Skip("set CHAINDORA_TEST_NPM to a trusted npm executable")
	}
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	fixture := buildTarball(t, map[string]string{
		"package.json": `{"name":"fixture","version":"1.0.0","dependencies":{"leaf":"1.0.0"},"scripts":{"postinstall":"node sentinel.js"}}`,
		"index.js":     `module.exports=require('leaf');`,
		"sentinel.js":  `require('fs').writeFileSync('lifecycle-ran','inert marker');`,
	})
	leaf := buildTarball(t, map[string]string{"package.json": `{"name":"leaf","version":"1.0.0"}`, "index.js": "module.exports=2;"})
	deps := map[string]string{"alias": "npm:fixture@1.0.0"}
	manifest, _ := json.Marshal(map[string]any{"name": "test-project", "version": "1.0.0", "dependencies": deps, "scripts": map[string]string{"preinstall": "node root-sentinel.js"}})
	lock, _ := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": map[string]any{
		"":                   map[string]any{"name": "test-project", "version": "1.0.0", "dependencies": deps},
		"node_modules/alias": map[string]any{"name": "fixture", "version": "1.0.0", "resolved": "https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz", "integrity": artifacts.SHA512(fixture), "dependencies": map[string]string{"leaf": "1.0.0"}, "hasInstallScript": true},
		"node_modules/leaf":  map[string]any{"version": "1.0.0", "resolved": "https://registry.npmjs.org/leaf/-/leaf-1.0.0.tgz", "integrity": artifacts.SHA512(leaf)},
	}})
	if err := os.WriteFile(filepath.Join(root, "package.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), lock, 0600); err != nil {
		t.Fatal(err)
	}
	// An inherited NODE_OPTIONS override must never reach the manager.
	t.Setenv("NODE_OPTIONS", "--require="+filepath.Join(root, "must-not-load.js"))
	t.Setenv("npm_config_registry", "https://invalid.example")
	client := &http.Client{Transport: transactionTransport(func(r *http.Request) (*http.Response, error) {
		data := fixture
		if strings.Contains(r.URL.Path, "/leaf/") {
			data = leaf
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
	})}
	tx, err := PrepareNPMTransaction(context.Background(), npm, root, []string{"install"}, client, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	}()
	if len(tx.Refs) != 2 || tx.Refs[0].Name != "fixture" || !tx.Refs[0].Direct || tx.Refs[1].Direct {
		t.Fatalf("wrong frozen graph: %+v", tx.Refs)
	}
	if err := tx.Install(context.Background()); err != nil {
		if pe, ok := err.(*PMError); ok {
			t.Fatalf("%v: %s", err, pe.Output)
		}
		t.Fatal(err)
	}
	for _, key := range []string{"alias", "leaf"} {
		if _, err := os.Stat(filepath.Join(root, "node_modules", key, "index.js")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "node_modules", "alias", "lifecycle-ran")); !os.IsNotExist(err) {
		t.Fatal("lifecycle ran")
	}
}

func TestNPMFrozenInstallFailurePreservesPreviousRealOffline(t *testing.T) {
	npm := os.Getenv("CHAINDORA_TEST_NPM")
	if npm == "" {
		t.Skip("set CHAINDORA_TEST_NPM to a trusted npm executable")
	}
	root, _, client := transactionFixture(t)
	// A stale lock must fail the real npm ci consistency check, leaving the
	// old installation untouched even after preparation and cache seeding.
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"test-project","version":"1.0.0","dependencies":{"fixture":"2.0.0"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	tx, err := PrepareNPMTransaction(context.Background(), npm, root, []string{"ci"}, client, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := os.MkdirAll(filepath.Join(root, "node_modules"), 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "node_modules", "old-marker")
	if err := os.WriteFile(marker, []byte("previous install"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := tx.Install(context.Background()); err == nil {
		t.Fatal("inconsistent lock accepted")
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "previous install" {
		t.Fatal("failed transaction damaged previous install")
	}
}
