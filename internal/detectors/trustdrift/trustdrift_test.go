package trustdrift

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// helper: write a file in a temp dir and return its path
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// === isCanonicalRegistry ===

func TestIsCanonicalRegistry(t *testing.T) {
	cases := []struct {
		name       string
		url        string
		canonicals []string
		want       bool
	}{
		{"npm exact", "https://registry.npmjs.org", []string{"https://registry.npmjs.org"}, true},
		{"npm trailing slash", "https://registry.npmjs.org/", []string{"https://registry.npmjs.org"}, true},
		{"npm case-insensitive", "HTTPS://REGISTRY.NPMJS.ORG", []string{"https://registry.npmjs.org"}, true},
		{"non-canonical", "https://npm.attacker.com", []string{"https://registry.npmjs.org"}, false},
		{"http downgrade", "http://registry.npmjs.org", []string{"https://registry.npmjs.org"}, false},
		{"empty url", "", []string{"https://registry.npmjs.org"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isCanonicalRegistry(c.url, c.canonicals...); got != c.want {
				t.Errorf("isCanonicalRegistry(%q) = %v, want %v", c.url, got, c.want)
			}
		})
	}
}

// === splitKV ===

func TestSplitKV(t *testing.T) {
	cases := []struct {
		line, k, v string
	}{
		{"foo=bar", "foo", "bar"},
		{"foo = bar", "foo", "bar"},
		{`foo="quoted"`, "foo", "quoted"},
		{"foo: bar", "foo", "bar"},
		{"no-separator", "", ""},
		{"=leading-equals", "", ""},
	}
	for _, c := range cases {
		t.Run(c.line, func(t *testing.T) {
			k, v := splitKV(c.line)
			if k != c.k || v != c.v {
				t.Errorf("splitKV(%q) = (%q, %q), want (%q, %q)", c.line, k, v, c.k, c.v)
			}
		})
	}
}

// === checkNPMRC ===

func TestCheckNPMRC_NoFindings_OnCanonicalRegistry(t *testing.T) {
	p := writeTemp(t, ".npmrc", `registry=https://registry.npmjs.org
//registry.npmjs.org/:_authToken=KEEP-OUT-OF-SCOPE`)
	if got := checkNPMRC(p); len(got) != 0 {
		t.Errorf("canonical npmjs.org should not emit findings, got %d", len(got))
	}
}

func TestCheckNPMRC_FlagsNonCanonicalRegistry(t *testing.T) {
	p := writeTemp(t, ".npmrc", `registry=https://npm.attacker.example`)
	got := checkNPMRC(p)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Severity != findings.SeverityMedium {
		t.Errorf("https override should be MEDIUM, got %v", got[0].Severity)
	}
	if got[0].VulnID != "TRUSTDRIFT-NPM-REGISTRY" {
		t.Errorf("wrong VulnID: %q", got[0].VulnID)
	}
}

func TestCheckNPMRC_HTTPDowngradeIsHigh(t *testing.T) {
	p := writeTemp(t, ".npmrc", `registry=http://internal.corp/npm`)
	got := checkNPMRC(p)
	if len(got) != 1 || got[0].Severity != findings.SeverityHigh {
		t.Errorf("plain-http registry should be HIGH; got %+v", got)
	}
}

func TestCheckNPMRC_IgnoresCommentsAndBlankLines(t *testing.T) {
	p := writeTemp(t, ".npmrc", `
# this is a comment
; this is also a comment

registry=https://registry.npmjs.org
`)
	if got := checkNPMRC(p); len(got) != 0 {
		t.Errorf("comments/blanks should be ignored; got %d findings", len(got))
	}
}

func TestCheckNPMRC_MissingFileReturnsNil(t *testing.T) {
	if got := checkNPMRC("/nonexistent/path/.npmrc"); got != nil {
		t.Errorf("missing file should return nil, got %v", got)
	}
}

// === checkPyPIRC ===

func TestCheckPyPIRC_FlagsCustomRepository(t *testing.T) {
	p := writeTemp(t, ".pypirc", `[distutils]
index-servers = main

[main]
repository = https://internal.corp/pypi
`)
	got := checkPyPIRC(p)
	if len(got) == 0 {
		t.Fatal("expected finding for custom pypi repository")
	}
}

func TestCheckPyPIRC_AcceptsPyPIDotOrg(t *testing.T) {
	p := writeTemp(t, ".pypirc", `[pypi]
repository = https://upload.pypi.org/legacy/
`)
	if got := checkPyPIRC(p); len(got) != 0 {
		t.Errorf("canonical pypi.org should not emit; got %d", len(got))
	}
}

// === checkPipConf ===

func TestCheckPipConf_FlagsCustomIndexURL(t *testing.T) {
	p := writeTemp(t, "pip.conf", `[global]
index-url = https://internal.corp/pypi/simple
`)
	got := checkPipConf(p)
	if len(got) == 0 || got[0].VulnID != "TRUSTDRIFT-PIP-INDEX" {
		t.Errorf("expected pip-index finding, got %+v", got)
	}
}

func TestCheckPipConf_HTTPIsHigh(t *testing.T) {
	p := writeTemp(t, "pip.conf", `[global]
index-url = http://internal/pypi/simple
`)
	got := checkPipConf(p)
	if len(got) != 1 || got[0].Severity != findings.SeverityHigh {
		t.Errorf("http pip-index should be HIGH; got %+v", got)
	}
}

// === checkCargoConfig ===

func TestCheckCargoConfig_FlagsReplaceWith(t *testing.T) {
	p := writeTemp(t, "config", `
[source.crates-io]
replace-with = "internal-mirror"

[source.internal-mirror]
registry = "https://internal/cargo"
`)
	got := checkCargoConfig(p)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].VulnID != "TRUSTDRIFT-CARGO-SOURCE" {
		t.Errorf("wrong VulnID: %q", got[0].VulnID)
	}
}

func TestCheckCargoConfig_CleanConfigIsClean(t *testing.T) {
	p := writeTemp(t, "config", `[build]
target-dir = "target"
`)
	if got := checkCargoConfig(p); len(got) != 0 {
		t.Errorf("clean config should emit nothing; got %d", len(got))
	}
}

// === checkGemRC ===

func TestCheckGemRC_FlagsMissingRubyGemsOrg(t *testing.T) {
	p := writeTemp(t, ".gemrc", `sources:
- https://internal.gems/
`)
	got := checkGemRC(p)
	if len(got) == 0 || got[0].VulnID != "TRUSTDRIFT-GEM-SOURCES" {
		t.Errorf("expected gem-sources finding, got %+v", got)
	}
}

func TestCheckGemRC_AcceptsCanonicalRubyGems(t *testing.T) {
	p := writeTemp(t, ".gemrc", `sources:
- https://rubygems.org/
`)
	if got := checkGemRC(p); len(got) != 0 {
		t.Errorf("canonical rubygems.org should not emit; got %d", len(got))
	}
}

// === checkGitConfig ===

func TestCheckGitConfig_FlagsInsteadOf(t *testing.T) {
	p := writeTemp(t, ".gitconfig", `[url "https://attacker.example/"]
insteadOf = https://github.com/
`)
	got := checkGitConfig(p)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Severity != findings.SeverityHigh {
		t.Errorf("insteadOf must be HIGH severity (owns every clone): %v", got[0].Severity)
	}
}

func TestCheckGitConfig_NoInsteadOfNoFinding(t *testing.T) {
	p := writeTemp(t, ".gitconfig", `[user]
email = me@example.com
name = Me
`)
	if got := checkGitConfig(p); len(got) != 0 {
		t.Errorf("clean gitconfig should not emit; got %d", len(got))
	}
}

// === checkEtcHosts ===

func TestCheckEtcHosts_FlagsRegistryHostnameOverride(t *testing.T) {
	p := writeTemp(t, "hosts", `127.0.0.1 localhost
10.0.0.5 registry.npmjs.org
`)
	got := checkEtcHosts(p)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].VulnID != "TRUSTDRIFT-ETC-HOSTS" {
		t.Errorf("wrong VulnID: %q", got[0].VulnID)
	}
	if !strings.Contains(got[0].Summary, "registry.npmjs.org") {
		t.Errorf("summary should name the hostname: %q", got[0].Summary)
	}
}

func TestCheckEtcHosts_FlagsSubdomain(t *testing.T) {
	p := writeTemp(t, "hosts", `1.2.3.4 sub.github.com
`)
	got := checkEtcHosts(p)
	if len(got) != 1 {
		t.Errorf("subdomain of suspicious host should be flagged; got %d", len(got))
	}
}

func TestCheckEtcHosts_IgnoresCommentsAndCleanLines(t *testing.T) {
	p := writeTemp(t, "hosts", `# comment
127.0.0.1 localhost
::1 localhost
`)
	if got := checkEtcHosts(p); len(got) != 0 {
		t.Errorf("clean hosts file should emit nothing; got %d", len(got))
	}
}

// === checkMavenSettings ===

func TestCheckMavenSettings_FlagsNonCanonicalMirror(t *testing.T) {
	p := writeTemp(t, "settings.xml", `<settings>
<mirrors><mirror><id>x</id><url>https://internal/maven</url><mirrorOf>*</mirrorOf></mirror></mirrors>
</settings>`)
	got := checkMavenSettings(p)
	if len(got) != 1 {
		t.Errorf("expected 1 maven-mirror finding, got %d", len(got))
	}
}

func TestCheckMavenSettings_AcceptsCanonicalCentral(t *testing.T) {
	p := writeTemp(t, "settings.xml", `<settings>
<mirrors><mirror><url>https://repo1.maven.org/maven2</url></mirror></mirrors>
</settings>`)
	if got := checkMavenSettings(p); len(got) != 0 {
		t.Errorf("canonical central mirror should not emit; got %d", len(got))
	}
}

// === checkGradleInit ===

func TestCheckGradleInit_FlagsCustomMavenBlockWithoutCentral(t *testing.T) {
	p := writeTemp(t, "init.gradle", `allprojects {
  repositories {
    maven { url 'https://internal/maven' }
  }
}`)
	got := checkGradleInit(p)
	if len(got) != 1 {
		t.Errorf("expected gradle-repo finding, got %d", len(got))
	}
}

func TestCheckGradleInit_AcceptsBlockWithMavenCentral(t *testing.T) {
	p := writeTemp(t, "init.gradle", `allprojects {
  repositories {
    mavenCentral()
    maven { url 'https://internal/maven' }
  }
}`)
	if got := checkGradleInit(p); len(got) != 0 {
		t.Errorf("block referencing mavenCentral() should not emit; got %d", len(got))
	}
}

// === checkSSHConfig ===

func TestCheckSSHConfig_FlagsProxyCommand(t *testing.T) {
	p := writeTemp(t, "config", `Host *
  ProxyCommand /usr/bin/nc %h %p
`)
	if got := checkSSHConfig(p); len(got) == 0 {
		t.Error("ProxyCommand should be flagged")
	}
}

func TestCheckSSHConfig_FlagsProxyJump(t *testing.T) {
	p := writeTemp(t, "config", `Host *.github.com
  ProxyJump bastion.attacker.example
`)
	if got := checkSSHConfig(p); len(got) == 0 {
		t.Error("ProxyJump should be flagged")
	}
}

func TestCheckSSHConfig_CleanFileEmitsNothing(t *testing.T) {
	p := writeTemp(t, "config", `Host github.com
  User git
  IdentityFile ~/.ssh/id_ed25519
`)
	if got := checkSSHConfig(p); len(got) != 0 {
		t.Errorf("clean ssh config should not emit; got %d", len(got))
	}
}

// === hashFile + baseline ===

func TestHashFile_StableAcrossReads(t *testing.T) {
	p := writeTemp(t, "x.txt", "hello\nworld\n")
	h1, exists, err := hashFile(p)
	if err != nil || !exists {
		t.Fatalf("first read: err=%v exists=%v", err, exists)
	}
	h2, _, _ := hashFile(p)
	if h1 != h2 {
		t.Errorf("hash unstable: %q vs %q", h1, h2)
	}
}

func TestHashFile_MissingFile(t *testing.T) {
	h, exists, err := hashFile(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Errorf("missing file should not error, got %v", err)
	}
	if exists {
		t.Errorf("missing file reported as exists")
	}
	if h != "" {
		t.Errorf("missing file should give empty hash, got %q", h)
	}
}

func TestSaveAndLoadBaseline_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "baseline.json")
	b := &baselineFile{
		CreatedAt: "2026-05-25T00:00:00Z",
		Hashes:    map[string]string{"/home/user/.npmrc": "abc123"},
	}
	if err := saveBaseline(p, b); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := loadBaseline(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Hashes["/home/user/.npmrc"] != "abc123" {
		t.Errorf("baseline round-trip lost data: %+v", got)
	}
}

func TestLoadBaseline_MissingFileReturnsNil(t *testing.T) {
	// loadBaseline returns (nil, nil) for missing files — the
	// "no baseline yet, this is the first run" signal that triggers
	// initial baseline creation.
	got, err := loadBaseline(filepath.Join(t.TempDir(), "no-such-baseline"))
	if err != nil {
		t.Errorf("missing baseline should not error, got %v", err)
	}
	if got != nil {
		t.Errorf("missing baseline should be nil for first-run signal, got %+v", got)
	}
}
