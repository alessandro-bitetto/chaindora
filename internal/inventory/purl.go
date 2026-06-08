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
	case EcosystemGoModules:
		typ = "golang"
	case EcosystemRubyGems:
		typ = "gem"
	case EcosystemCrates:
		typ = "cargo"
	case EcosystemMavenCentral:
		typ = "maven"
	case EcosystemHomebrew:
		typ = "brew"
	case EcosystemDebian:
		typ = "deb"
	case EcosystemBrowserExt:
		typ = "browserext"
	case EcosystemIDEExt:
		typ = "ideext"
	case EcosystemNuGet:
		typ = "nuget"
	case EcosystemPackagist:
		typ = "composer"
	case EcosystemPub:
		typ = "pub"
	case EcosystemHex:
		typ = "hex"
	case EcosystemSwift:
		typ = "swift"
	case EcosystemHackage:
		typ = "hackage"
	case EcosystemCRAN:
		typ = "cran"
	case EcosystemJulia:
		typ = "julia"
	case EcosystemConda:
		typ = "conda"
	case EcosystemConan:
		typ = "conan"
	case EcosystemVcpkg:
		typ = "vcpkg"
	case EcosystemOpam:
		typ = "opam"
	case EcosystemCocoaPods:
		typ = "cocoapods"
	case EcosystemCarthage:
		typ = "carthage"
	case EcosystemCPAN:
		typ = "cpan"
	case EcosystemLuaRocks:
		typ = "luarocks"
	case EcosystemNimble:
		typ = "nimble"
	case EcosystemShards:
		typ = "shards"
	case EcosystemZig:
		typ = "zig"
	case EcosystemElm:
		typ = "elm"
	case EcosystemMCP:
		// Non-standard PURL type for MCP servers; chaindora-local
		// until/unless the purl-spec adopts an MCP type.
		typ = "mcp"
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
	// Docker and Go module names commonly span path segments
	// (registry/namespace/image; github.com/owner/repo/subpath). Preserve
	// them as PURL path separators rather than URL-encoding the slashes.
	if eco == EcosystemDocker || eco == EcosystemGoModules {
		parts := strings.Split(name, "/")
		for i, p := range parts {
			parts[i] = purlEscape(p)
		}
		return "pkg:" + typ + "/" + strings.Join(parts, "/") + "@" + version
	}
	return "pkg:" + typ + "/" + purlEscape(name) + "@" + version
}
