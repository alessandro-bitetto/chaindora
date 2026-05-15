package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePnpmLock(t *testing.T) {
	content := `lockfileVersion: '6.0'
packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-xxx}
  /@babel/code-frame@7.10.4:
    resolution: {integrity: sha512-yyy}
  /foo@1.0.0(peer@2.0.0):
    resolution: {integrity: sha512-zzz}
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "pnpm-lock.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parsePnpmLock(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"lodash":            "4.17.21",
		"@babel/code-frame": "7.10.4",
		"foo":               "1.0.0",
	}
	if len(pkgs) != len(want) {
		t.Fatalf("got %d, want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for _, p := range pkgs {
		w, ok := want[p.Name]
		if !ok || p.Version != w {
			t.Errorf("unexpected %s@%s; want %v", p.Name, p.Version, want)
		}
	}
}

func TestParsePnpmKey(t *testing.T) {
	cases := []struct {
		in            string
		wantName      string
		wantVersion   string
	}{
		{"/lodash@4.17.21", "lodash", "4.17.21"},
		{"/@babel/code-frame@7.10.4", "@babel/code-frame", "7.10.4"},
		{"/foo@1.0.0(peer@2.0.0)", "foo", "1.0.0"},
		{"lodash@4.17.21", "lodash", "4.17.21"},
		{"/no-version", "", ""},
	}
	for _, c := range cases {
		gotName, gotVer := parsePnpmKey(c.in)
		if gotName != c.wantName || gotVer != c.wantVersion {
			t.Errorf("parsePnpmKey(%q) = (%q,%q), want (%q,%q)", c.in, gotName, gotVer, c.wantName, c.wantVersion)
		}
	}
}
