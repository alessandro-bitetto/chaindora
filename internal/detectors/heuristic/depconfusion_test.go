package heuristic

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// fakeProbe is a deterministic stand-in for registries.Probe used by the
// heuristic tests. Each instance maps package name → existence (and
// optionally publish date + downloads) and counts how many lookups
// happened so the tests can assert "we didn't even call the network".
type fakeProbe struct {
	exists    map[string]bool
	published map[string]time.Time
	downloads map[string]int
	calls     int
}

func newFakeProbe() *fakeProbe {
	return &fakeProbe{
		exists:    map[string]bool{},
		published: map[string]time.Time{},
		downloads: map[string]int{},
	}
}

func (f *fakeProbe) Exists(_ context.Context, name string) (bool, error) {
	f.calls++
	return f.exists[name], nil
}
func (f *fakeProbe) PublishedAt(_ context.Context, name string) (time.Time, error) {
	f.calls++
	return f.published[name], nil
}
func (f *fakeProbe) DownloadsLast7d(_ context.Context, name string) (int, error) {
	f.calls++
	if d, ok := f.downloads[name]; ok {
		return d, nil
	}
	return -1, nil
}

func TestDepConfusion_NoPrivateSignal_DoesNotFire(t *testing.T) {
	// v0.6.0 semantics: a scoped package with no .npmrc mapping and no
	// private resolved URL is presumed PUBLIC, so no finding even if
	// the colliding name happens to exist on npm.
	tmp := t.TempDir()
	probe := newFakeProbe()
	probe.exists["@vitejs/plugin-react"] = true // legitimately public
	inv := &inventory.Inventory{Packages: []inventory.Package{
		{Ecosystem: inventory.EcosystemNPM, Name: "@vitejs/plugin-react", Version: "4.0.0", ResolvedURL: "https://registry.npmjs.org/@vitejs/plugin-react/-/plugin-react-4.0.0.tgz"},
	}}
	got := detectDepConfusion(context.Background(), inv, tmp, Config{NPMProbe: probe})
	if len(got) != 0 {
		t.Fatalf("expected no findings for a public scope, got %d: %+v", len(got), got)
	}
}

func TestDepConfusion_NpmrcPrivateScope_PublicCollision_Critical(t *testing.T) {
	tmp := t.TempDir()
	npmrc := "@my-company:registry=https://artifactory.corp/npm\n"
	_ = os.WriteFile(filepath.Join(tmp, ".npmrc"), []byte(npmrc), 0o644)
	probe := newFakeProbe()
	probe.exists["@my-company/auth"] = true // attacker registered the name publicly
	inv := &inventory.Inventory{Packages: []inventory.Package{
		{Ecosystem: inventory.EcosystemNPM, Name: "@my-company/auth", Version: "1.0.0"},
	}}
	got := detectDepConfusion(context.Background(), inv, tmp, Config{NPMProbe: probe})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Severity != findings.SeverityCritical {
		t.Errorf("private + public collision should be CRITICAL, got %q", got[0].Severity)
	}
}

func TestDepConfusion_NpmrcPrivateScope_NoCollision_Medium(t *testing.T) {
	tmp := t.TempDir()
	npmrc := "@my-company:registry=https://artifactory.corp/npm\n"
	_ = os.WriteFile(filepath.Join(tmp, ".npmrc"), []byte(npmrc), 0o644)
	probe := newFakeProbe() // empty: nothing exists publicly
	inv := &inventory.Inventory{Packages: []inventory.Package{
		{Ecosystem: inventory.EcosystemNPM, Name: "@my-company/auth", Version: "1.0.0"},
	}}
	got := detectDepConfusion(context.Background(), inv, tmp, Config{NPMProbe: probe})
	if len(got) != 1 {
		t.Fatalf("expected 1 MEDIUM defensive-claim finding, got %d", len(got))
	}
	if got[0].Severity != findings.SeverityMedium {
		t.Errorf("private + no public collision should be MEDIUM, got %q", got[0].Severity)
	}
}

func TestDepConfusion_PrivateResolvedURL_Triggers(t *testing.T) {
	// Even without .npmrc, if the lockfile's resolved URL points to a
	// private registry, we know the scope is private for this project.
	tmp := t.TempDir()
	probe := newFakeProbe()
	probe.exists["@my-company/auth"] = true
	inv := &inventory.Inventory{Packages: []inventory.Package{
		{
			Ecosystem:   inventory.EcosystemNPM,
			Name:        "@my-company/auth",
			Version:     "1.0.0",
			ResolvedURL: "https://artifactory.corp/api/npm/npm-local/@my-company/auth/-/auth-1.0.0.tgz",
		},
	}}
	got := detectDepConfusion(context.Background(), inv, tmp, Config{NPMProbe: probe})
	if len(got) != 1 || got[0].Severity != findings.SeverityCritical {
		t.Errorf("expected 1 CRITICAL via resolved-URL signal, got %+v", got)
	}
}

func TestDepConfusion_DedupesByScope(t *testing.T) {
	tmp := t.TempDir()
	npmrc := "@x:registry=https://artifactory.corp/npm\n"
	_ = os.WriteFile(filepath.Join(tmp, ".npmrc"), []byte(npmrc), 0o644)
	probe := newFakeProbe()
	probe.exists["@x/a"] = true
	inv := &inventory.Inventory{Packages: []inventory.Package{
		{Ecosystem: inventory.EcosystemNPM, Name: "@x/a", Version: "1.0"},
		{Ecosystem: inventory.EcosystemNPM, Name: "@x/b", Version: "1.0"},
		{Ecosystem: inventory.EcosystemNPM, Name: "@x/c", Version: "1.0"},
	}}
	got := detectDepConfusion(context.Background(), inv, tmp, Config{NPMProbe: probe})
	if len(got) != 1 {
		t.Errorf("expected dedup to 1 finding per scope, got %d", len(got))
	}
}

func TestDepConfusion_OfflineNoProbe_DoesNotPanic(t *testing.T) {
	// nil probe → cfg.npm() returns Noop, which says "no" to everything.
	// Without a public-collision signal, the heuristic should not fire
	// even though .npmrc marks the scope private. Conservative: rather
	// no finding than a wrong-confidence one.
	tmp := t.TempDir()
	npmrc := "@my-company:registry=https://artifactory.corp/npm\n"
	_ = os.WriteFile(filepath.Join(tmp, ".npmrc"), []byte(npmrc), 0o644)
	inv := &inventory.Inventory{Packages: []inventory.Package{
		{Ecosystem: inventory.EcosystemNPM, Name: "@my-company/auth", Version: "1.0.0"},
	}}
	got := detectDepConfusion(context.Background(), inv, tmp, Config{})
	// Noop probe says exists=false, so this is the MEDIUM "no public
	// collision yet" path — still a useful finding because the scope
	// IS private (signal 1 satisfied) and the user should defensively
	// claim the name regardless of probe availability.
	if len(got) != 1 || got[0].Severity != findings.SeverityMedium {
		t.Errorf("offline + private signal → MEDIUM finding expected, got %+v", got)
	}
}

func TestIsPrivateResolvedURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"", false},
		{"https://registry.npmjs.org/foo/-/foo-1.0.0.tgz", false},
		{"https://artifactory.corp/api/npm/repo/foo/-/foo-1.0.0.tgz", true},
		{"https://npm.pkg.github.com/download/@scope/pkg/1.0.0/...", true},
		{"file:./local/foo.tgz", false},
		{"git+https://github.com/foo/bar.git#main", false},
		{"https://my.private.registry.example.com/foo", true},
	}
	for _, c := range cases {
		if got := isPrivateResolvedURL(c.url); got != c.want {
			t.Errorf("isPrivateResolvedURL(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}
