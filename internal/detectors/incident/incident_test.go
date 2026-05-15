package incident

import (
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, rel string
		want         bool
	}{
		{"**/data.json", "data.json", true},
		{"**/data.json", "src/data.json", true},
		{"**/data.json", "a/b/c/data.json", true},
		{"**/data.json", "data.json.bak", false},
		{"**/.github/workflows/foo.yml", "x/y/.github/workflows/foo.yml", true},
		{"**/.github/workflows/foo.yml", ".github/workflows/foo.yml", true},
		{"**/.github/workflows/foo.yml", ".github/workflows/bar.yml", false},
		{"src/main.go", "src/main.go", true},
		{"src/main.go", "other/main.go", false},
		{"*.txt", "foo.txt", true},
		{"*.txt", "sub/foo.txt", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.rel); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.rel, got, c.want)
		}
	}
}

func TestNormalizeEcosystem(t *testing.T) {
	cases := []struct {
		in  string
		out inventory.Ecosystem
	}{
		{"npm", inventory.EcosystemNPM},
		{"NPM", inventory.EcosystemNPM},
		{"PyPI", inventory.EcosystemPyPI},
		{"pypi", inventory.EcosystemPyPI},
		{"GitHub Actions", inventory.EcosystemActions},
		{"githubactions", inventory.EcosystemActions},
	}
	for _, c := range cases {
		if got := normalizeEcosystem(c.in); got != c.out {
			t.Errorf("normalizeEcosystem(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"critical", "CRITICAL"},
		{"HIGH", "HIGH"},
		{"medium", "MEDIUM"},
		{"moderate", "MEDIUM"},
		{"low", "LOW"},
		{"???", "UNKNOWN"},
	}
	for _, c := range cases {
		if got := parseSeverity(c.in); string(got) != c.want {
			t.Errorf("parseSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
