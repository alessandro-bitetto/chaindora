package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePipRequirements(t *testing.T) {
	content := `# Comment line
urllib3==1.26.4
requests==2.25.0  # inline comment
flask[async]==2.0.0
-r other.txt
django>=4.0
boto3==1.20.0; python_version >= '3.8'
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "requirements.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parsePipRequirements(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"urllib3":  "1.26.4",
		"requests": "2.25.0",
		"flask":    "2.0.0",
		"boto3":    "1.20.0",
	}
	if len(pkgs) != len(want) {
		t.Errorf("expected %d packages, got %d: %+v", len(want), len(pkgs), pkgs)
	}
	for _, p := range pkgs {
		w, ok := want[p.Name]
		if !ok {
			t.Errorf("unexpected: %s@%s", p.Name, p.Version)
			continue
		}
		if p.Version != w {
			t.Errorf("%s: got %s, want %s", p.Name, p.Version, w)
		}
	}
}

func TestNormalizePyPIName(t *testing.T) {
	cases := []struct{ in, out string }{
		{"Pillow", "pillow"},
		{"foo.bar.baz", "foo-bar-baz"},
		{"foo_bar", "foo-bar"},
		{"FOO-bar.baz_qux", "foo-bar-baz-qux"},
		{"foo___bar", "foo-bar"},
	}
	for _, c := range cases {
		got := normalizePyPIName(c.in)
		if got != c.out {
			t.Errorf("normalize(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}

func TestParsePoetryLock(t *testing.T) {
	content := `# A poetry.lock fragment
[[package]]
name = "urllib3"
version = "1.26.4"
description = "..."

[[package]]
name = "Requests"
version = "2.25.0"
description = "..."

[metadata]
lockfile-version = "2.0"
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "poetry.lock")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parsePoetryLock(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"urllib3":  "1.26.4",
		"requests": "2.25.0",
	}
	if len(pkgs) != len(want) {
		t.Fatalf("expected %d packages, got %d: %+v", len(want), len(pkgs), pkgs)
	}
	for _, p := range pkgs {
		w, ok := want[p.Name]
		if !ok || p.Version != w {
			t.Errorf("%s@%s not expected; want %v", p.Name, p.Version, want)
		}
	}
}
