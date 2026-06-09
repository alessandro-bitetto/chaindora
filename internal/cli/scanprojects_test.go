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

	got := discoverProjects(root, nil, false)
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

// TestDiscoverProjectsGitOnly — the opt-in focus mode keeps only roots
// inside a git work tree (the repo itself, or a project nested under one),
// and drops non-versioned trees like a downloaded/extracted package.
func TestDiscoverProjectsGitOnly(t *testing.T) {
	root := t.TempDir()
	mkfile := func(rel string) {
		full := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mkfile("repo/.git/HEAD")
	mkfile("repo/package.json")
	// A downloaded, non-versioned package.
	mkfile("downloaded-pkg/package.json")

	all := discoverProjects(root, nil, false)
	gitOnly := discoverProjects(root, nil, true)
	sort.Strings(gitOnly)

	if len(all) <= len(gitOnly) {
		t.Fatalf("git-only should drop the non-versioned root; all=%v gitOnly=%v", all, gitOnly)
	}
	want := []string{filepath.Join(root, "repo")}
	if !reflect.DeepEqual(gitOnly, want) {
		t.Errorf("\n got: %v\nwant: %v", gitOnly, want)
	}
}

func TestWithinGitRepo(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "repo", ".git"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "repo", "nested", "deep"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "loose"), 0o755)

	if !withinGitRepo(filepath.Join(root, "repo"), root) {
		t.Error("repo with its own .git should be within a git repo")
	}
	if !withinGitRepo(filepath.Join(root, "repo", "nested", "deep"), root) {
		t.Error("dir nested under a .git ancestor should be within a git repo")
	}
	if withinGitRepo(filepath.Join(root, "loose"), root) {
		t.Error("dir with no .git ancestor (bounded at scanRoot) should not be within a git repo")
	}
}

func TestCollapseNestedRoots(t *testing.T) {
	// collapseNestedRoots uses filepath.Separator for nesting detection, so
	// the test paths need to be constructed via filepath.Join to work on both
	// Unix (/) and Windows (\).
	in := []string{
		filepath.Join("home", "u", "proj"),
		filepath.Join("home", "u", "proj", "packages", "a"),
		filepath.Join("home", "u", "proj", "packages", "b"),
		filepath.Join("home", "u", "other"),
	}
	sort.Strings(in)
	got := collapseNestedRoots(in)
	want := []string{
		filepath.Join("home", "u", "other"),
		filepath.Join("home", "u", "proj"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCollapseNestedRootsRespectsSiblings(t *testing.T) {
	in := []string{"a", "aa", "aaa"} // siblings, not nested
	sort.Strings(in)
	got := collapseNestedRoots(in)
	want := []string{"a", "aa", "aaa"}
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
