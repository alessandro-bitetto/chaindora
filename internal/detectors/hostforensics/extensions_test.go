package hostforensics

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

func TestScanVSCodeExtensions(t *testing.T) {
	home := t.TempDir()
	mk := func(rel, content string) {
		full := filepath.Join(home, rel)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// VSCode extension WITH package.json (preferred path)
	mk(".vscode/extensions/ms-python.python-2024.0.1/package.json",
		`{"name":"python","publisher":"ms-python","version":"2024.0.1"}`)
	// VSCode extension WITHOUT package.json (fall back to dir name parse)
	_ = os.MkdirAll(filepath.Join(home, ".vscode/extensions/foo.bar-1.0.0"), 0o755)
	// Cursor extension
	mk(".cursor/extensions/cursor.cursor-0.30.0/package.json",
		`{"name":"cursor","publisher":"cursor","version":"0.30.0"}`)
	// Dotfile dir (should be skipped)
	_ = os.MkdirAll(filepath.Join(home, ".vscode/extensions/.obsolete"), 0o755)

	pkgs := scanVSCodeExtensions(home)
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 extensions, got %d: %+v", len(pkgs), pkgs)
	}
	byName := map[string]string{}
	for _, p := range pkgs {
		byName[p.Name] = p.Version
		if p.Ecosystem != inventory.EcosystemIDEExt {
			t.Errorf("%s wrong ecosystem: %s", p.Name, p.Ecosystem)
		}
	}
	if byName["ms-python.python"] != "2024.0.1" {
		t.Errorf("ms-python.python version: %v", byName)
	}
	if byName["foo.bar"] != "1.0.0" {
		t.Errorf("dir-name-parsed extension wrong: %v", byName)
	}
	if byName["cursor.cursor"] != "0.30.0" {
		t.Errorf("cursor extension wrong: %v", byName)
	}
}

func TestScanChromiumExtensions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses macOS path layout; cross-platform coverage adequately tested by Linux/macOS CI matrix")
	}
	home := t.TempDir()
	// Construct a fake Chrome Default profile.
	var root string
	switch runtime.GOOS {
	case "darwin":
		root = filepath.Join(home, "Library", "Application Support", "Google", "Chrome")
	default:
		root = filepath.Join(home, ".config", "google-chrome")
	}
	extPath := filepath.Join(root, "Default", "Extensions", "aaaaabbbbbcccccdddddeeeeefffff00", "1.2.3")
	if err := os.MkdirAll(extPath, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"name":"Test Extension","version":"1.2.3","manifest_version":3}`
	if err := os.WriteFile(filepath.Join(extPath, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgs := scanChromiumExtensions(home)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 chromium extension, got %d: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "aaaaabbbbbcccccdddddeeeeefffff00" || pkgs[0].Version != "1.2.3" {
		t.Errorf("wrong package: %+v", pkgs[0])
	}
}

func TestScanExtensionsAggregates(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".vscode/extensions/x.y-1.0.0"), 0o755)
	inv := ScanExtensions(home)
	if len(inv.Packages) != 1 {
		t.Errorf("expected 1 package, got %d", len(inv.Packages))
	}
	if len(inv.Sources) != 1 {
		t.Errorf("expected 1 source, got %d", len(inv.Sources))
	}
}
