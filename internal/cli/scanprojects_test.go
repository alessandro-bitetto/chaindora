package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestDiscoverProjects(t *testing.T) {
	root := t.TempDir()
	mkfile := func(rel string) {
		full := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mkfile("proj-a/package.json")
	mkfile("proj-a/src/index.js")
	mkfile("proj-b/requirements.txt")
	mkfile("proj-c/services/api/Dockerfile")
	mkfile("proj-c/services/api/Dockerfile.dev")
	mkfile("proj-c/services/web/package.json")
	// Should be skipped (in node_modules)
	mkfile("proj-a/node_modules/dep/package.json")
	// Should be skipped (in .git)
	mkfile("proj-a/.git/HEAD")
	// .github/workflows folder marks parent as a project too
	mkfile("proj-d/.github/workflows/ci.yml")

	got := discoverProjects(root, nil)
	sort.Strings(got)

	want := []string{
		filepath.Join(root, "proj-a"),
		filepath.Join(root, "proj-b"),
		filepath.Join(root, "proj-c", "services", "api"),
		filepath.Join(root, "proj-c", "services", "web"),
		filepath.Join(root, "proj-d"),
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got: %v\nwant: %v", got, want)
	}
}

func TestCollapseNestedRoots(t *testing.T) {
	in := []string{
		"/home/u/proj",
		"/home/u/proj/packages/a",
		"/home/u/proj/packages/b",
		"/home/u/other",
	}
	sort.Strings(in)
	got := collapseNestedRoots(in)
	want := []string{"/home/u/other", "/home/u/proj"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCollapseNestedRootsRespectsSiblings(t *testing.T) {
	in := []string{"/a", "/aa", "/aaa"} // not nested despite prefix collision
	sort.Strings(in)
	got := collapseNestedRoots(in)
	want := []string{"/a", "/aa", "/aaa"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestIsProjectMarker(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"package.json", true},
		{"Dockerfile", true},
		{"Dockerfile.dev", true},
		{"dockerfile", true},
		{"go.mod", true},
		{".gitlab-ci.yml", true},
		{"random.txt", false},
		{"Dockerfileish", false},
		{"package.json.bak", false},
	}
	for _, c := range cases {
		if got := isProjectMarker(c.name); got != c.want {
			t.Errorf("isProjectMarker(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
