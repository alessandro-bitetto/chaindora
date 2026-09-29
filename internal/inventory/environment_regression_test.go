package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDenoLockFormatsAndPeerIdentities(t *testing.T) {
	for _, fixture := range []struct{ name, data string }{
		{"v3", `{"version":"3","npm":{"packages":{"@scope/pkg@1.2.3_peer@4.0.0":{"integrity":"sha512-fixture"}}}}`},
		{"v4", `{"version":"4","npm":{"@scope/pkg@1.2.3_peer@4.0.0":{"integrity":"sha512-fixture"}}}`},
		{"v5", `{"version":"5","npm":{"@scope/pkg@1.2.3(peer@4.0.0)":{"integrity":"sha512-fixture"}}}`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			pkgs, err := ParseDenoLockData([]byte(fixture.data))
			if err != nil {
				t.Fatal(err)
			}
			if len(pkgs) != 1 || pkgs[0].Name != "@scope/pkg" || pkgs[0].Version != "1.2.3" || pkgs[0].Integrity != "sha512-fixture" {
				t.Fatalf("lost or corrupted resolved identity: %+v", pkgs)
			}
		})
	}
}

func TestDenoLockRejectsIncompleteOrUnsupportedData(t *testing.T) {
	for _, data := range []string{
		`{"version":"5",`, `null`, `{}`, `{"version":"99","npm":{}}`,
		`{"version":"5","npm":[]}`, `{"version":"5","npm":{"pkg":{}}}`,
		`{"version":"3","npm":{"packages":{"pkg@":{}}}}`,
	} {
		if _, err := ParseDenoLockData([]byte(data)); err == nil {
			t.Errorf("accepted incomplete input %s", data)
		}
	}
}

func TestPaketConstraintsAreNotResolvedPackages(t *testing.T) {
	data := "NUGET\r\n  remote: https://example.invalid/feed\r\n    Root (2.0.0)\r\n      Leaf (>= 1.0)\r\n    Leaf (1.2.3)\r\nGROUP Build\r\nNUGET\r\n  remote: https://example.invalid/feed\r\n    Leaf (1.2.3)\r\nGITHUB\r\n    Ignored (9.0.0)\r\n"
	pkgs, err := ParsePaketLockData([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 || pkgs[0].Name != "Root" || pkgs[1].Name != "Leaf" || pkgs[1].Version != "1.2.3" {
		t.Fatalf("nested constraint or unrelated source leaked into inventory: %+v", pkgs)
	}
	for _, data := range []string{"garbage", "NUGET\n    broken record\n", "NUGET\n    Leaf (>=1.0)\n"} {
		if _, err := ParsePaketLockData([]byte(data)); err == nil {
			t.Errorf("accepted malformed lock %q", data)
		}
	}
}

func TestPyprojectExactPinsRemainVersionMatchable(t *testing.T) {
	for _, c := range []struct{ spec, version string }{
		{"fixture==1.2.3", "1.2.3"}, {"fixture==1.2.*", "==1.2.*"},
		{"fixture>=1.2.3", ">=1.2.3"}, {"fixture==1.2.3,!=1.2.4", "==1.2.3,!=1.2.4"},
	} {
		path := filepath.Join(t.TempDir(), "pyproject.toml")
		if err := os.WriteFile(path, []byte("[project]\ndependencies = [\""+c.spec+"\"]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		pkgs, err := parsePyprojectManifest(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(pkgs) != 1 || pkgs[0].Name != "fixture" || pkgs[0].Version != c.version {
			t.Fatalf("%s: got %+v", c.spec, pkgs)
		}
	}
}
