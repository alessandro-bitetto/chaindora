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

		// Renamed / extracted module trees (Docker volumes, etc.).
		{"/Users/me/OrbStack/docker/volumes/mvp_be_node_modules", "mvp_be_node_modules", true},
		{"/foo/fe_node_modules", "fe_node_modules", true},

		// Container / VM product data dirs.
		{"/Users/me/OrbStack", "OrbStack", true},
		{"/Users/me/.orbstack", ".orbstack", true},
		{"/Users/me/.colima", ".colima", true},
		{"/Users/me/.docker", ".docker", true},
		{"/var/lib/docker/volumes/x", "volumes", true}, // Linux docker storage, matched by path

		// Should NOT skip
		{"/foo/src", "src", false},
		{"/foo/lib", "lib", false},
		{"/foo/pkg", "pkg", false},
		// A source repo that merely contains docker/volumes/ examples
		// must NOT be skipped (we match the Linux storage root by path,
		// not the basename "volumes" anywhere).
		{"/Users/me/work/infra/docker/volumes", "volumes", false},
		{"/Users/me/work/node_modules_helper", "node_modules_helper", false},

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
