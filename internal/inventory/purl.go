package inventory

import (
	"net/url"
	"strings"
)

// purlEscape encodes a PURL path segment. url.PathEscape preserves "@"
// because RFC 3986 allows it in path segments, but PURL conventionally
// percent-encodes "@" to avoid ambiguity with the version separator.
func purlEscape(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), "@", "%40")
}

// PURL builds a Package URL identifier per https://github.com/package-url/purl-spec
//   pkg:<type>/[<namespace>/]<name>@<version>
func PURL(eco Ecosystem, name, version string) string {
	var typ string
	switch eco {
	case EcosystemNPM:
		typ = "npm"
	case EcosystemPyPI:
		typ = "pypi"
	case EcosystemActions:
		typ = "githubactions"
	default:
		typ = strings.ToLower(string(eco))
	}

	// npm scoped packages: "@scope/pkg" → namespace "@scope", name "pkg"
	if eco == EcosystemNPM && strings.HasPrefix(name, "@") {
		if i := strings.Index(name, "/"); i > 0 {
			ns := purlEscape(name[:i])
			n := purlEscape(name[i+1:])
			return "pkg:" + typ + "/" + ns + "/" + n + "@" + version
		}
	}
	// GitHub Actions: "owner/repo" → namespace "owner", name "repo"
	if eco == EcosystemActions {
		if i := strings.Index(name, "/"); i > 0 {
			ns := purlEscape(name[:i])
			n := purlEscape(name[i+1:])
			return "pkg:" + typ + "/" + ns + "/" + n + "@" + version
		}
	}
	return "pkg:" + typ + "/" + purlEscape(name) + "@" + version
}
