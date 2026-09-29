package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRetiredInventoriesAreIgnored(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"Gemfile.lock", "pom.xml", "composer.lock", "pubspec.lock", "mix.lock", "Package.resolved", "stack.yaml.lock", "renv.lock", "Manifest.toml", "environment.yml", "Podfile.lock", "gradle.lockfile", "mcp.json"} {
		// Invalid content would produce an inventory error if a retired parser
		// were still dispatched. These files must be completely ignored.
		if err := os.WriteFile(filepath.Join(dir, name), []byte("invalid removed inventory\x00"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inv, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Packages) != 0 || len(inv.Sources) != 0 || len(inv.Errors) != 0 {
		t.Fatalf("retired inventory dispatched: %+v", inv)
	}
}
