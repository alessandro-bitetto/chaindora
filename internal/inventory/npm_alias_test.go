package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNPMAliasUsesCanonicalIdentity(t *testing.T) {
	p := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(p, []byte(`{"lockfileVersion":3,"packages":{"node_modules/harmless-alias":{"name":"actual-package","version":"1.0.0"},"node_modules/direct":{"version":"2.0.0"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	packages, err := parseNPMPackageLock(p)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, p := range packages {
		names[p.Name] = true
	}
	if !names["actual-package"] || !names["direct"] || names["harmless-alias"] {
		t.Fatalf("wrong identities: %+v", packages)
	}
}

func TestNPMV1ScopedAliasUsesCanonicalIdentity(t *testing.T) {
	p := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(p, []byte(`{"lockfileVersion":1,"dependencies":{"alias":{"version":"npm:@scope/actual@1.2.3","integrity":"sha512-test"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	packages, err := parseNPMPackageLock(p)
	if err != nil || len(packages) != 1 || packages[0].Name != "@scope/actual" || packages[0].Version != "1.2.3" || packages[0].Integrity != "sha512-test" {
		t.Fatalf("alias identity lost: %+v %v", packages, err)
	}
}
