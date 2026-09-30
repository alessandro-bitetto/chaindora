package gate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/artifacts"
)

func TestAllowlistTerminatesChecksButDenyAndIntegrityWin(t *testing.T) {
	ref := PackageRef{Ecosystem: "npm", Name: "fixture", Version: "1.0.0"}
	cfg := &Config{Allow: map[string][]string{"npm": {"fixture@1.0.0"}}}
	for _, cached := range []bool{false, true} {
		block := &scriptedChecker{name: "must-not-run", result: CheckResult{Verdict: VerdictBlock}}
		stack := []Checker{&AllowlistChecker{Config: cfg}, block}
		var results []PackageCheck
		if cached {
			results = CachedRun(context.Background(), stack, []PackageRef{ref}, newTestCache(t))
		} else {
			results = Run(context.Background(), stack, []PackageRef{ref})
		}
		if results[0].Decision() != VerdictApprove || block.callCount() != 0 {
			t.Fatalf("allow did not short circuit: %+v", results)
		}
	}
	cfg.Deny = map[string][]string{"npm": {"fixture"}}
	if Run(context.Background(), []Checker{&AllowlistChecker{Config: cfg}}, []PackageRef{ref})[0].Decision() != VerdictBlock {
		t.Fatal("deny must win")
	}
	cfg.Deny = nil
	cache := newTestCache(t)
	ref.Integrity = "sha512-original"
	if err := cache.Store(ref, approvedCheck("test")); err != nil {
		t.Fatal(err)
	}
	ref.Integrity = "sha512-changed"
	if CachedRun(context.Background(), []Checker{&AllowlistChecker{Config: cfg}}, []PackageRef{ref}, cache)[0].Decision() != VerdictBlock {
		t.Fatal("allow bypassed integrity")
	}
}

func TestConfigRejectsMalformedUnknownAndMultipleDocuments(t *testing.T) {
	for _, input := range []string{"deny: [", "allow_on_unkown: true", "deny: {}\n---\nallow: {}"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "chaindora.yml"), []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(dir); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}

func TestNPMAliasChecksCanonicalIdentity(t *testing.T) {
	data := []byte(`{"packages":{"node_modules/alias":{"name":"actual","version":"1.0.0"}}}`)
	refs, err := parseNPMLockTree(data, []string{"alias@npm:actual@1.0.0"})
	if err != nil || len(refs) != 1 || refs[0].Name != "actual" || !refs[0].Direct {
		t.Fatalf("%+v %v", refs, err)
	}
}

func TestStaticBindsSnapshotToIntegrity(t *testing.T) {
	clean := buildTarball(t, map[string]string{"index.js": "module.exports=1;"})
	scan := NewStaticScan()
	scan.Probes = probesWith("npm", stubProbe{tarballURL: "fixture", tarballContents: clean})
	ref := PackageRef{Ecosystem: "npm", Name: "fixture", Version: "1.0.0", Integrity: artifacts.SHA512([]byte("wrong"))}
	if got := scan.Check(context.Background(), ref); got.Verdict != VerdictBlock {
		t.Fatalf("mismatched bytes accepted: %+v", got)
	}
	ref.Integrity = artifacts.SHA512(clean)
	ref.ArtifactPath = filepath.Join(t.TempDir(), "artifact.tgz")
	if err := os.WriteFile(ref.ArtifactPath, clean, 0600); err != nil {
		t.Fatal(err)
	}
	// The registry changes after the snapshot. The current inspection must
	// continue to use only the bytes that will actually be installed.
	scan.Probes = probesWith("npm", stubProbe{fetchErr: context.DeadlineExceeded})
	if got := scan.Check(context.Background(), ref); got.Verdict != VerdictApprove {
		t.Fatalf("snapshot not used: %+v", got)
	}
	if err := os.WriteFile(ref.ArtifactPath, []byte("modified snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := scan.Check(context.Background(), ref); got.Verdict != VerdictBlock {
		t.Fatalf("snapshot mutation accepted: %+v", got)
	}
}

func TestExceptionDoesNotSeedIntegrityHistory(t *testing.T) {
	cache := NewCache(t.TempDir(), time.Hour)
	ref := PackageRef{Ecosystem: "npm", Name: "fixture", Version: "1", Integrity: "sha512-fixture"}
	CachedRun(context.Background(), []Checker{&AllowlistChecker{Config: &Config{Allow: map[string][]string{"npm": {"fixture"}}}}}, []PackageRef{ref}, cache)
	if cache.Lookup(ref) != nil {
		t.Fatal("exception was recorded as verified approval")
	}
}
