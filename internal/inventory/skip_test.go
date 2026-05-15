package inventory

import "testing"

func TestShouldSkipDir(t *testing.T) {
	cases := []struct {
		path, name string
		want       bool
	}{
		// Common skips
		{"/foo/node_modules", "node_modules", true},
		{"/foo/.venv", ".venv", true},
		{"/foo/.git", ".git", true},
		{"/foo/testdata", "testdata", true},
		{"/foo/.vscode", ".vscode", true},
		{"/foo/.cursor", ".cursor", true},
		{"/foo/Library", "Library", true},
		{"/foo/AppData", "AppData", true},
		{"/foo/Cellar", "Cellar", true},
		{"/foo/dist", "dist", true},
		{"/foo/__pycache__", "__pycache__", true},

		// Should NOT skip
		{"/foo/src", "src", false},
		{"/foo/lib", "lib", false},
		{"/foo/pkg", "pkg", false},

		// Go module cache: mod skipped only when parent is pkg.
		{"/Users/me/go/pkg/mod", "mod", true},
		{"/var/lib/dpkg/pkg/mod", "mod", true},
		{"/foo/mod", "mod", false},
		{"/foo/bar/mod", "mod", false},
	}
	for _, c := range cases {
		got := ShouldSkipDir(c.path, c.name)
		if got != c.want {
			t.Errorf("ShouldSkipDir(%q, %q) = %v, want %v", c.path, c.name, got, c.want)
		}
	}
}
