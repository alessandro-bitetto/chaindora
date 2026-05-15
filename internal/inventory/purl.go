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
	case EcosystemGitLabCI:
		typ = "gitlabci"
	case EcosystemBitbucketPipes:
		typ = "bitbucketpipes"
	case EcosystemCircleCIOrbs:
		typ = "circleciorbs"
	case EcosystemAzurePipelines:
		typ = "azurepipelines"
	case EcosystemDocker:
		typ = "docker"
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
	// owner/repo-style names: split on the first "/" into namespace + name.
	// Skip when the name has a special prefix (e.g. GitLab CI's "template:" /
	// "remote:") that contains a colon — those aren't owner/repo paths.
	switch eco {
	case EcosystemActions, EcosystemBitbucketPipes, EcosystemCircleCIOrbs:
		if i := strings.Index(name, "/"); i > 0 {
			ns := purlEscape(name[:i])
			n := purlEscape(name[i+1:])
			return "pkg:" + typ + "/" + ns + "/" + n + "@" + version
		}
	case EcosystemGitLabCI:
		if !strings.Contains(name, ":") {
			if i := strings.Index(name, "/"); i > 0 {
				ns := purlEscape(name[:i])
				n := purlEscape(name[i+1:])
				return "pkg:" + typ + "/" + ns + "/" + n + "@" + version
			}
		}
	}
	// Docker image names commonly span path segments (registry/namespace/image).
	// Preserve them as PURL path separators rather than URL-encoding the slashes.
	if eco == EcosystemDocker {
		parts := strings.Split(name, "/")
		for i, p := range parts {
			parts[i] = purlEscape(p)
		}
		return "pkg:" + typ + "/" + strings.Join(parts, "/") + "@" + version
	}
	return "pkg:" + typ + "/" + purlEscape(name) + "@" + version
}
