package cli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPickAssets(t *testing.T) {
	version := "0.4.0"
	assets := []releaseAsset{
		{Name: "chaindora_0.4.0_linux_x86_64.tar.gz"},
		{Name: "chaindora_0.4.0_linux_arm64.tar.gz"},
		{Name: "chaindora_0.4.0_darwin_x86_64.tar.gz"},
		{Name: "chaindora_0.4.0_darwin_arm64.tar.gz"},
		{Name: "chaindora_0.4.0_windows_x86_64.zip"},
		{Name: "chaindora_0.4.0_windows_arm64.zip"},
		{Name: "chaindora_0.4.0_checksums.txt"},
	}
	cases := []struct {
		goos, goarch, want string
	}{
		{"linux", "amd64", "chaindora_0.4.0_linux_x86_64.tar.gz"},
		{"linux", "arm64", "chaindora_0.4.0_linux_arm64.tar.gz"},
		{"darwin", "amd64", "chaindora_0.4.0_darwin_x86_64.tar.gz"},
		{"darwin", "arm64", "chaindora_0.4.0_darwin_arm64.tar.gz"},
		{"windows", "amd64", "chaindora_0.4.0_windows_x86_64.zip"},
		{"windows", "arm64", "chaindora_0.4.0_windows_arm64.zip"},
	}
	for _, c := range cases {
		t.Run(c.goos+"/"+c.goarch, func(t *testing.T) {
			a, cs, err := pickAssets(assets, version, c.goos, c.goarch)
			if err != nil {
				t.Fatalf("pickAssets: %v", err)
			}
			if a.Name != c.want {
				t.Errorf("archive: got %q, want %q", a.Name, c.want)
			}
			if cs.Name != "chaindora_0.4.0_checksums.txt" {
				t.Errorf("checksum: got %q", cs.Name)
			}
		})
	}
}

func TestPickAssetsMissing(t *testing.T) {
	// Checksums file but no archive for the requested platform.
	assets := []releaseAsset{
		{Name: "chaindora_0.4.0_linux_x86_64.tar.gz"},
		{Name: "chaindora_0.4.0_checksums.txt"},
	}
	if _, _, err := pickAssets(assets, "0.4.0", "openbsd", "amd64"); err == nil {
		t.Fatal("expected error for unsupported os")
	}
	// Archive present but no checksums file.
	if _, _, err := pickAssets(assets[:1], "0.4.0", "linux", "amd64"); err == nil {
		t.Fatal("expected error when checksums file missing")
	}
}

func TestVerifyChecksum(t *testing.T) {
	archive := []byte("pretend this is a tarball")
	sum := sha256.Sum256(archive)
	hexSum := hex.EncodeToString(sum[:])
	checksums := []byte(
		hexSum + "  chaindora_0.4.0_linux_x86_64.tar.gz\n" +
			"0000000000000000000000000000000000000000000000000000000000000000  chaindora_0.4.0_darwin_x86_64.tar.gz\n",
	)
	if err := verifyChecksum(archive, "chaindora_0.4.0_linux_x86_64.tar.gz", checksums); err != nil {
		t.Errorf("happy path: %v", err)
	}
	if err := verifyChecksum(archive, "chaindora_0.4.0_darwin_x86_64.tar.gz", checksums); err == nil {
		t.Error("expected mismatch error")
	}
	if err := verifyChecksum(archive, "chaindora_0.4.0_windows_x86_64.zip", checksums); err == nil {
		t.Error("expected missing-entry error")
	}
}

func makeTarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func makeZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractFromTarGz(t *testing.T) {
	want := []byte("fake-chdora-binary")
	archive := makeTarGz(t, map[string][]byte{
		"LICENSE":   []byte("apache-2.0"),
		"chdora":    want,
		"README.md": []byte("# hi"),
	})
	got, err := extractFromTarGz(archive, "chdora")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("body mismatch: got %q, want %q", got, want)
	}
	if _, err := extractFromTarGz(archive, "missing"); err == nil {
		t.Error("expected error for missing entry")
	}
}

func TestExtractFromZip(t *testing.T) {
	want := []byte("fake-chdora.exe")
	archive := makeZip(t, map[string][]byte{
		"LICENSE":       []byte("apache-2.0"),
		"chdora.exe": want,
	})
	got, err := extractFromZip(archive, "chdora.exe")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("body mismatch")
	}
}

func TestExtractBinaryDispatch(t *testing.T) {
	tgz := makeTarGz(t, map[string][]byte{"chdora": []byte("tgz-body")})
	zp := makeZip(t, map[string][]byte{"chdora.exe": []byte("zip-body")})

	got, err := extractBinary(tgz, "chaindora_0.4.0_linux_x86_64.tar.gz", "chdora")
	if err != nil || string(got) != "tgz-body" {
		t.Errorf("tar.gz dispatch: %v / %q", err, got)
	}
	got, err = extractBinary(zp, "chaindora_0.4.0_windows_x86_64.zip", "chdora.exe")
	if err != nil || string(got) != "zip-body" {
		t.Errorf("zip dispatch: %v / %q", err, got)
	}
}

func TestReplaceBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The Windows path renames the running .exe; we can't simulate
		// a "running" file in a unit test, but the Unix-side rename
		// covers the common atomic-swap logic.
		t.Skip("skipping rename test on windows")
	}
	dir := t.TempDir()
	self := filepath.Join(dir, "chdora")
	if err := os.WriteFile(self, []byte("old-body"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceBinary(self, []byte("new-body")); err != nil {
		t.Fatalf("replaceBinary: %v", err)
	}
	got, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new-body" {
		t.Errorf("body: got %q", got)
	}
	st, err := os.Stat(self)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o100 == 0 {
		t.Errorf("not executable: mode %v", st.Mode())
	}
	// No tmp file should be left behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "chaindora-upgrade-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestPackageManagerHint(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/opt/homebrew/bin/chdora", "Homebrew (brew upgrade chdora)"},
		{"/usr/local/Cellar/chdora/0.5.0/bin/chdora", "Homebrew (brew upgrade chdora)"},
		{"/home/linuxbrew/.linuxbrew/bin/chdora", "Homebrew (brew upgrade chdora)"},
		{"/snap/chdora/current/bin/chdora", "snap (snap refresh chdora)"},
		{"/Users/me/go/bin/chdora", ""},
		{"/usr/local/bin/chdora", ""},
		{"C:\\Users\\me\\bin\\chdora.exe", ""},
	}
	for _, c := range cases {
		got := packageManagerHint(c.path)
		if got != c.want {
			t.Errorf("packageManagerHint(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestFetchRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/releases/latest":
			fmt.Fprintln(w, `{"tag_name":"v0.4.0","html_url":"https://x/0.4.0","assets":[{"name":"chaindora_0.4.0_linux_x86_64.tar.gz","browser_download_url":"https://x/a"}]}`)
		case "/repos/o/r/releases/tags/v0.3.0":
			fmt.Fprintln(w, `{"tag_name":"v0.3.0","html_url":"https://x/0.3.0","assets":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := srv.Client()

	rel, err := fetchRelease(ctx, client, srv.URL+"/repos/o/r/releases/latest", "")
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if rel.TagName != "v0.4.0" {
		t.Errorf("tag: got %q", rel.TagName)
	}
	if len(rel.Assets) != 1 {
		t.Errorf("assets: got %d", len(rel.Assets))
	}

	rel, err = fetchRelease(ctx, client, srv.URL+"/repos/o/r/releases/latest", "v0.3.0")
	if err != nil {
		t.Fatalf("pinned: %v", err)
	}
	if rel.TagName != "v0.3.0" {
		t.Errorf("pinned tag: got %q", rel.TagName)
	}

	// Pinning without "v" prefix should also work.
	rel, err = fetchRelease(ctx, client, srv.URL+"/repos/o/r/releases/latest", "0.3.0")
	if err != nil || rel.TagName != "v0.3.0" {
		t.Errorf("unprefixed pin: %v / %q", err, rel.TagName)
	}

	if _, err := fetchRelease(ctx, client, srv.URL+"/repos/o/r/releases/latest", "v9.9.9"); err == nil {
		t.Error("expected error for missing tag")
	}
}

func TestUpgradeDownload(t *testing.T) {
	body := []byte("payload")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/asset") {
			w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := upgradeDownload(ctx, srv.Client(), srv.URL+"/asset")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("body mismatch")
	}
	if _, err := upgradeDownload(ctx, srv.Client(), srv.URL+"/missing"); err == nil {
		t.Error("expected status error")
	}
	if _, err := upgradeDownload(ctx, srv.Client(), ""); err == nil {
		t.Error("expected empty-URL error")
	}
}
