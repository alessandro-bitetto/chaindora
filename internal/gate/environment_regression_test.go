package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Cross-platform subprocess double: the test binary exits before its test
// runner starts. This executes no package code and requires no shell/toolchain.
func init() {
	if os.Getenv("CHAINDORA_TEST_DENO_FAILURE") == "1" && len(os.Args) > 1 && os.Args[1] == "install" {
		fmt.Fprintln(os.Stderr, "fixture resolution failed")
		os.Exit(42)
	}
}

func TestDenoResolverNeverApprovesStaleLockAfterFailure(t *testing.T) {
	dir := t.TempDir()
	data := `{"version":"5","npm":{"fixture@1.0.0":{"integrity":"sha512-fixture"}}}`
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CHAINDORA_TEST_DENO_FAILURE", "1")
	refs, err := ResolveDenoTree(context.Background(), bin, dir)
	var pmErr *PMError
	if len(refs) != 0 || !errors.As(err, &pmErr) || pmErr.ExitCode != 42 {
		t.Fatalf("failed resolution must retain PM error, never use stale lock: refs=%+v err=%v", refs, err)
	}
}

func TestPaketResolverRefusesEmptyInspection(t *testing.T) {
	for _, lock := range []string{"invalid", "NUGET\n  remote: https://example.invalid/feed\n"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "paket.lock"), []byte(lock), 0o600); err != nil {
			t.Fatal(err)
		}
		if refs, err := ResolvePaketTree(context.Background(), "", dir); err == nil || len(refs) != 0 {
			t.Fatalf("approved empty/incomplete Paket lock: %+v, %v", refs, err)
		}
	}
}

func TestUVSkipsOnlyLocalProjectSources(t *testing.T) {
	data := `[[package]]
name = "local-root"
version = "0.0.0"
source = { virtual = "." }

[[package]]
name = "chdora-gate-resolve"
version = "1.2.3"
source = { registry = "https://pypi.org/simple" }
wheels = [{ hash = "sha256:fixture" }]
`
	refs := parseUVLockTree([]byte(data), nil)
	if len(refs) != 1 || refs[0].Name != "chdora-gate-resolve" || refs[0].Version != "1.2.3" {
		t.Fatalf("filter must use source, not package name: %+v", refs)
	}
}

func TestYarnBerrySkipsWorkspaceRoot(t *testing.T) {
	data := `__metadata:
  version: 8
"root@workspace:.":
  version: 0.0.0-use.local
  resolution: "root@workspace:."
"fixture@npm:1.2.3":
  version: 1.2.3
  resolution: "fixture@npm:1.2.3"
  checksum: fixture-hash
`
	refs, err := parseYarnBerryLock([]byte(data), []string{"fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Name != "fixture" || !refs[0].Direct || refs[0].Integrity != "fixture-hash" {
		t.Fatalf("workspace became registry dependency: %+v", refs)
	}
}
