package inventory

import "testing"

func TestPURL(t *testing.T) {
	cases := []struct {
		name    string
		eco     Ecosystem
		pkg     string
		version string
		want    string
	}{
		{"npm plain", EcosystemNPM, "lodash", "4.17.20", "pkg:npm/lodash@4.17.20"},
		{"npm scoped", EcosystemNPM, "@ctrl/tinycolor", "4.1.1", "pkg:npm/%40ctrl/tinycolor@4.1.1"},
		{"npm scoped dashes", EcosystemNPM, "@scope/pkg-name", "1.0.0", "pkg:npm/%40scope/pkg-name@1.0.0"},
		{"pypi", EcosystemPyPI, "urllib3", "1.26.4", "pkg:pypi/urllib3@1.26.4"},
		{"gh-actions owner/repo", EcosystemActions, "actions/checkout", "v3", "pkg:githubactions/actions/checkout@v3"},
		{"gh-actions another", EcosystemActions, "github/super-linter", "v5.0.0", "pkg:githubactions/github/super-linter@v5.0.0"},
		{"docker plain", EcosystemDocker, "nginx", "1.25", "pkg:docker/nginx@1.25"},
		{"docker library/name", EcosystemDocker, "library/nginx", "1.25", "pkg:docker/library/nginx@1.25"},
		{"docker registry path", EcosystemDocker, "gcr.io/distroless/static-debian12", "nonroot", "pkg:docker/gcr.io/distroless/static-debian12@nonroot"},
		{"docker digest version", EcosystemDocker, "nginx", "sha256:abc", "pkg:docker/nginx@sha256:abc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := PURL(c.eco, c.pkg, c.version)
			if got != c.want {
				t.Errorf("PURL = %q, want %q", got, c.want)
			}
		})
	}
}
