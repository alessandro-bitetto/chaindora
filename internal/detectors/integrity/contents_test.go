package integrity

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/artifacts"
)

func TestInstalledFilesAgainstVerifiedArchive(t *testing.T) {
	files := map[string]string{"package.json": `{"name":"actual","version":"1.0.0"}`, "index.js": "module.exports=1;"}
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "package/" + name, Mode: 0644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	data := b.Bytes()
	hash := artifacts.SHA512(data)
	for _, change := range []string{"clean", "changed", "missing", "extra", "no-evidence", "corrupt-cache"} {
		t.Run(change, func(t *testing.T) {
			root := t.TempDir()
			cache := t.TempDir()
			installed := filepath.Join(root, "node_modules", "alias")
			if err := os.MkdirAll(installed, 0700); err != nil {
				t.Fatal(err)
			}
			for name, content := range files {
				if err := os.WriteFile(filepath.Join(installed, name), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			lock, _ := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": map[string]any{"node_modules/alias": map[string]any{"name": "actual", "version": "1.0.0", "integrity": hash, "resolved": "https://registry.npmjs.org/actual/-/actual-1.0.0.tgz"}}})
			lockPath := filepath.Join(root, "package-lock.json")
			if err := os.WriteFile(lockPath, lock, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(artifacts.CachePath(cache, hash), data, 0600); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "changed":
				if err := os.WriteFile(filepath.Join(installed, "index.js"), []byte("module.exports=2;"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(filepath.Join(installed, "index.js")); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := os.WriteFile(filepath.Join(installed, "extra.js"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "no-evidence":
				if err := os.Remove(artifacts.CachePath(cache, hash)); err != nil {
					t.Fatal(err)
				}
			case "corrupt-cache":
				if err := os.WriteFile(artifacts.CachePath(cache, hash), []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			d := New([]string{root})
			d.Offline = true
			d.ArtifactCacheRoot = cache
			out, err := d.Detect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if change == "clean" {
				if len(out) != 0 {
					t.Fatalf("clean alias flagged: %+v", out)
				}
				return
			}
			want := "INTEGRITY-FILE-MISMATCH"
			if change == "no-evidence" || change == "corrupt-cache" {
				want = IncompleteID
			}
			found := false
			for _, f := range out {
				if f.VulnID == want {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s missed: %+v", change, out)
			}
		})
	}
}
