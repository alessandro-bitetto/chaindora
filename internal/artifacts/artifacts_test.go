package artifacts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func testArchive(t *testing.T, names []string, kind byte) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tr := tar.NewWriter(gz)
	for _, name := range names {
		content := []byte("module.exports=1;")
		if name == "package/package.json" {
			content = []byte(`{"name":"fixture","version":"1.0.0"}`)
		}
		h := &tar.Header{Name: name, Typeflag: kind, Mode: 0644, Size: int64(len(content))}
		if kind == tar.TypeSymlink {
			h.Size = 0
			h.Linkname = "/outside"
			content = nil
		}
		if err := tr.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestIntegrityEnforcesStrongestDigest(t *testing.T) {
	data := []byte("inert fixture")
	h := sha256.Sum256(data)
	weak := "sha256-" + base64.StdEncoding.EncodeToString(h[:])
	for _, hash := range []string{SHA512(data), weak, weak + " " + SHA512(data)} {
		if err := VerifyIntegrity(data, hash); err != nil {
			t.Fatal(err)
		}
	}
	for _, hash := range []string{"", "h9:unsupported", "sha512-invalid", SHA512([]byte("other")), weak + " " + SHA512([]byte("other"))} {
		if err := VerifyIntegrity(data, hash); err == nil {
			t.Errorf("accepted %q", hash)
		}
	}
}

func TestManifestRejectsAmbiguousArchives(t *testing.T) {
	for _, names := range [][]string{{"package/package.json", "package/../outside"}, {"package/package.json", "/absolute"}, {"package/package.json", "package/index.js", "package/index.js"}, {"package/package.json", "another/file"}, {"package/package.json", "package/C:/file"}, {"package/package.json", "package/a\\b"}} {
		data := testArchive(t, names, tar.TypeReg)
		if _, err := NPMManifest(data, SHA512(data)); err == nil {
			t.Errorf("accepted %v", names)
		}
	}
	data := testArchive(t, []string{"package/link"}, tar.TypeSymlink)
	if _, err := NPMManifest(data, SHA512(data)); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestVerifiedFileComparison(t *testing.T) {
	data := testArchive(t, []string{"package/package.json", "package/index.js"}, tar.TypeReg)
	m, err := NPMManifest(data, SHA512(data))
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"clean", "changed", "missing", "extra", "symlink"} {
		t.Run(change, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"fixture","version":"1.0.0"}`), 0600); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(root, "index.js")
			if err := os.WriteFile(file, []byte("module.exports=1;"), 0600); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "changed":
				if err := os.WriteFile(file, []byte("module.exports=2;"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := os.WriteFile(filepath.Join(root, "extra.js"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), file); err != nil {
					t.Skip(err)
				}
			}
			diffs, err := CompareFiles(root, m)
			if err != nil {
				t.Fatal(err)
			}
			if (len(diffs) == 0) != (change == "clean") {
				t.Fatalf("%s: %+v", change, diffs)
			}
		})
	}
}

func TestInstalledDirectoriesRejectSymlinkedParents(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "node_modules")); err != nil {
		t.Skip(err)
	}
	if err := os.MkdirAll(filepath.Join(outside, "fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := DirectoryPath(root, "node_modules/fixture"); err == nil {
		t.Fatal("followed a symlinked installation parent")
	}
}
