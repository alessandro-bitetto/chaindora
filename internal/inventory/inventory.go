package inventory

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// Ecosystem corresponds to OSV.dev ecosystem identifiers where applicable.
type Ecosystem string

const (
	EcosystemNPM            Ecosystem = "npm"
	EcosystemPyPI           Ecosystem = "PyPI"
	EcosystemActions        Ecosystem = "GitHub Actions"
	EcosystemGitLabCI       Ecosystem = "GitLab CI"
	EcosystemBitbucketPipes Ecosystem = "Bitbucket Pipes"
	EcosystemCircleCIOrbs   Ecosystem = "CircleCI Orbs"
	EcosystemAzurePipelines Ecosystem = "Azure Pipelines"
	EcosystemDocker         Ecosystem = "Docker"
	EcosystemHomebrew       Ecosystem = "Homebrew"
	EcosystemDebian         Ecosystem = "Debian"
	EcosystemBrowserExt     Ecosystem = "Browser Extension"
	EcosystemIDEExt         Ecosystem = "IDE Extension"
	EcosystemGoModules      Ecosystem = "Go"
	// v0.11 ecosystems
	EcosystemRubyGems     Ecosystem = "RubyGems"
	EcosystemCrates       Ecosystem = "crates.io"
	EcosystemMavenCentral Ecosystem = "Maven Central"
	// v0.15 ecosystems — added to extend detection-side parity with the
	// v0.14 gate-side coverage push. Each has a lockfile that exposes
	// content hashes, so predictive + republish-guard light up
	// automatically once the parser populates inventory.Package.Integrity.
	EcosystemNuGet     Ecosystem = "NuGet"
	EcosystemPackagist Ecosystem = "Packagist" // Composer
	EcosystemPub       Ecosystem = "Pub"       // Dart / Flutter
	EcosystemHex       Ecosystem = "Hex"       // Elixir / Erlang
	// v0.15 full-parity push — every remaining v0.14 gate-side
	// ecosystem with a parseable lockfile, so detection-side coverage
	// matches prevention-side coverage as closely as the ecosystems
	// allow. Behavioral signal varies per ecosystem: those covered by
	// OSV (Swift, Hackage, CRAN) get vuln data automatically; the rest
	// rely on the cache-driven republish-guard alone until gate Probes
	// land per ecosystem.
	EcosystemSwift     Ecosystem = "SwiftURL"
	EcosystemHackage   Ecosystem = "Hackage"
	EcosystemCRAN      Ecosystem = "CRAN"
	EcosystemJulia     Ecosystem = "Julia"
	EcosystemConda     Ecosystem = "Conda"
	EcosystemConan     Ecosystem = "ConanCenter"
	EcosystemVcpkg     Ecosystem = "vcpkg"
	EcosystemOpam      Ecosystem = "opam"
	EcosystemCocoaPods Ecosystem = "CocoaPods"
	EcosystemCarthage  Ecosystem = "Carthage"
	EcosystemCPAN      Ecosystem = "CPAN"
	EcosystemLuaRocks  Ecosystem = "LuaRocks"
	EcosystemNimble    Ecosystem = "Nimble"
	EcosystemShards    Ecosystem = "Shards"
	EcosystemZig       Ecosystem = "Zig"
	EcosystemElm       Ecosystem = "Elm"

	// EcosystemMCP — Model Context Protocol server inventory. Not a
	// package registry; the "package" here is the launcher spec
	// declared in an MCP client's config (Claude Desktop, mcp.json,
	// Cline, Gemini, etc.). Borrowed from bumblebee's MCP parser.
	// Added v0.17 to land the auditor on the v0.18 roadmap a release
	// early. No OSV mapping — MCP servers aren't tracked in a vuln
	// database, so the value here is inventory-only (knowing which
	// MCP servers are configured across the fleet when an advisory
	// names a specific server).
	EcosystemMCP Ecosystem = "MCP"
)

// Package represents one resolved dependency discovered in a manifest or lockfile.
type Package struct {
	Ecosystem  Ecosystem `json:"ecosystem"`
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	PURL       string    `json:"purl"`
	SourcePath string    `json:"source_path"`
	// Pinned reports whether a ref is pinned to a SHA / digest. For
	// GitHub-style actions that's a 40-char commit SHA; for Docker images
	// it's a sha256 digest.
	Pinned bool `json:"pinned,omitempty"`
	// HasInstallScript reports whether the package declares a pre/post-install
	// hook. Currently populated only for npm packages, from the lockfile's
	// `hasInstallScript` metadata.
	HasInstallScript bool `json:"has_install_script,omitempty"`
	// ResolvedURL is the URL the package was actually fetched from, as
	// recorded by the lockfile. For npm, this is the `resolved` field; for
	// yarn/pnpm, the equivalent. Used by the dep-confusion heuristic to
	// distinguish "resolved from npmjs.org" (public, no risk) from
	// "resolved from artifactory.corp/..." (private scope, real risk if
	// the same name exists publicly).
	ResolvedURL string `json:"resolved_url,omitempty"`
	// Integrity is the lockfile-recorded content hash for this version
	// (e.g. "sha512-..." for npm, "sha256:..." for cargo, "h1:..." for
	// Go modules). v0.15+. Used by the predictive detector to fire
	// republish-guard via the gate-cache: a known (name, version) seen
	// before with a DIFFERENT Integrity is a maintainer-account-takeover
	// signal. Empty when the ecosystem's lockfile doesn't expose it.
	Integrity string `json:"integrity,omitempty"`
	// AliasOf is the real package name an install alias resolves to.
	// Yarn records aliases as `string-width-cjs@npm:string-width@^4.2.0`:
	// the directory installs under the alias name (string-width-cjs) but
	// the package's own metadata reports the real name (string-width).
	// Empty for plain installs. The integrity name-drift check compares
	// the on-disk package.json name against this declared target instead
	// of the directory name, so legitimate aliases don't read as a swap.
	// (npm records the same fact on its lockfile entry's own `name`
	// field; pnpm keys its packages: map on the real name — neither needs
	// this carried through inventory.)
	AliasOf string `json:"alias_of,omitempty"`
}

// Source identifies a manifest file that was successfully parsed.
type Source struct {
	Path      string    `json:"path"`
	Ecosystem Ecosystem `json:"ecosystem"`
	Kind      string    `json:"kind"`
}

// Inventory is the result of scanning a tree.
type Inventory struct {
	Packages []Package `json:"packages"`
	Sources  []Source  `json:"sources"`
	Errors   []string  `json:"errors,omitempty"`
}

// ScanOption configures behavior of Scan. See WithExcludes.
type ScanOption func(*scanCfg)

type scanCfg struct {
	excludeNames map[string]struct{}
}

// WithExcludes adds directory basenames to skip during the walk. Useful for
// ignoring vendored test fixtures, build outputs, or other paths not covered
// by Scan's built-in skip list (node_modules / .venv / venv / .git).
func WithExcludes(names ...string) ScanOption {
	return func(c *scanCfg) {
		if c.excludeNames == nil {
			c.excludeNames = map[string]struct{}{}
		}
		for _, n := range names {
			if n != "" {
				c.excludeNames[n] = struct{}{}
			}
		}
	}
}

// Scan walks root and parses any known lockfiles/manifests it finds.
func Scan(root string, opts ...ScanOption) (*Inventory, error) {
	cfg := &scanCfg{}
	for _, o := range opts {
		o(cfg)
	}
	inv := &Inventory{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			inv.Errors = append(inv.Errors, err.Error())
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			// Don't skip the user-supplied root even if its basename
			// matches the skip list (e.g. `chdora scan testdata`
			// should actually scan testdata, not refuse to descend
			// into it just because the basename is in the default
			// skip set).
			if path != root {
				if ShouldSkipDir(path, name) {
					return filepath.SkipDir
				}
			}
			if _, skip := cfg.excludeNames[name]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		base := filepath.Base(path)

		// Suffix-matched manifest fallbacks. Handled BEFORE the
		// basename switch so we can dispatch on .csproj / .fsproj /
		// .vbproj (file-suffix patterns, not exact basenames).
		// These manifest parsers only fire when no resolved
		// lockfile sibling exists — when the user has the real
		// lockfile, the lockfile parser is more precise and wins.
		switch {
		case strings.HasSuffix(base, ".csproj"),
			strings.HasSuffix(base, ".fsproj"),
			strings.HasSuffix(base, ".vbproj"):
			if hasNuGetLockfileSibling(path) {
				return nil // real lockfile took precedence
			}
			pkgs, perr := parseCsprojManifest(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, base+" "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemNuGet, Kind: base + " (manifest fallback)"})
			return nil
		}

		switch base {
		case "package-lock.json":
			pkgs, perr := parseNPMPackageLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "package-lock.json "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemNPM, Kind: "package-lock.json"})
		case "requirements.txt":
			pkgs, perr := parsePipRequirements(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "requirements.txt "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemPyPI, Kind: "requirements.txt"})
		case "poetry.lock":
			pkgs, perr := parsePoetryLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "poetry.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemPyPI, Kind: "poetry.lock"})
		case "yarn.lock":
			pkgs, perr := parseYarnLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "yarn.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemNPM, Kind: "yarn.lock"})
		case "pnpm-lock.yaml":
			pkgs, perr := parsePnpmLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "pnpm-lock.yaml "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemNPM, Kind: "pnpm-lock.yaml"})
		case "uv.lock":
			pkgs, perr := parseUVLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "uv.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemPyPI, Kind: "uv.lock"})
		case "Pipfile.lock":
			pkgs, perr := parsePipfileLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "Pipfile.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemPyPI, Kind: "Pipfile.lock"})
		case "go.mod":
			pkgs, perr := parseGoMod(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "go.mod "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemGoModules, Kind: "go.mod"})
		case "Gemfile.lock":
			pkgs, perr := parseGemfileLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "Gemfile.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemRubyGems, Kind: "Gemfile.lock"})
		case "Cargo.lock":
			pkgs, perr := parseCargoLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "Cargo.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemCrates, Kind: "Cargo.lock"})
		case "pom.xml":
			pkgs, perr := parseMavenPOM(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "pom.xml "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemMavenCentral, Kind: "pom.xml"})
		case "packages.lock.json":
			pkgs, perr := parseNuGetPackagesLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "packages.lock.json "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemNuGet, Kind: "packages.lock.json"})
		case "composer.lock":
			pkgs, perr := parseComposerLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "composer.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemPackagist, Kind: "composer.lock"})
		case "pubspec.lock":
			pkgs, perr := parsePubspecLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "pubspec.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemPub, Kind: "pubspec.lock"})
		case "mix.lock":
			pkgs, perr := parseMixLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "mix.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemHex, Kind: "mix.lock"})
		case "Package.resolved":
			pkgs, perr := parsePackageResolved(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "Package.resolved "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemSwift, Kind: "Package.resolved"})
		case "stack.yaml.lock":
			pkgs, perr := parseStackYamlLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "stack.yaml.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemHackage, Kind: "stack.yaml.lock"})
		case "cabal.project.freeze":
			pkgs, perr := parseCabalProjectFreeze(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "cabal.project.freeze "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemHackage, Kind: "cabal.project.freeze"})
		case "renv.lock":
			pkgs, perr := parseRenvLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "renv.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemCRAN, Kind: "renv.lock"})
		case "Manifest.toml":
			pkgs, perr := parseJuliaManifest(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "Manifest.toml "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemJulia, Kind: "Manifest.toml"})
		case "conda-lock.yml", "conda-lock.yaml":
			pkgs, perr := parseCondaLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "conda-lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemConda, Kind: "conda-lock"})
		case "conan.lock":
			pkgs, perr := parseConanLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "conan.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemConan, Kind: "conan.lock"})
		case "vcpkg.json":
			pkgs, perr := parseVcpkgManifest(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "vcpkg.json "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemVcpkg, Kind: "vcpkg.json"})
		case "deno.lock":
			pkgs, perr := parseDenoLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "deno.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemNPM, Kind: "deno.lock"})
		case "pdm.lock":
			pkgs, perr := parsePDMLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "pdm.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemPyPI, Kind: "pdm.lock"})
		case "paket.lock":
			pkgs, perr := parsePaketLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "paket.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemNuGet, Kind: "paket.lock"})
		case "Podfile.lock":
			pkgs, perr := parsePodfileLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "Podfile.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemCocoaPods, Kind: "Podfile.lock"})
		case "Cartfile.resolved":
			pkgs, perr := parseCartfileResolved(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "Cartfile.resolved "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemCarthage, Kind: "Cartfile.resolved"})
		case "cpanfile.snapshot":
			pkgs, perr := parseCpanfileSnapshot(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "cpanfile.snapshot "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemCPAN, Kind: "cpanfile.snapshot"})
		case "nimble.lock":
			pkgs, perr := parseNimbleLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "nimble.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemNimble, Kind: "nimble.lock"})
		case "shard.lock":
			pkgs, perr := parseShardLock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "shard.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemShards, Kind: "shard.lock"})
		case "build.zig.zon":
			pkgs, perr := parseZigZon(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "build.zig.zon "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemZig, Kind: "build.zig.zon"})
		case "elm.json":
			pkgs, perr := parseElmJSON(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "elm.json "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemElm, Kind: "elm.json"})
		case "rebar.lock":
			pkgs, perr := parseRebar3Lock(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "rebar.lock "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemHex, Kind: "rebar.lock"})
		case "gradle.lockfile":
			pkgs, perr := parseGradleLockfile(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "gradle.lockfile "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemMavenCentral, Kind: "gradle.lockfile"})
		case "build.gradle", "build.gradle.kts":
			// Manifest fallback — only fires when no gradle.lockfile sibling.
			if hasGradleLockfileSibling(path) {
				return nil
			}
			pkgs, perr := parseGradleManifest(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, base+" "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemMavenCentral, Kind: base + " (manifest fallback)"})
		case "composer.json":
			if hasComposerLockSibling(path) {
				return nil // composer.lock parser is more precise
			}
			pkgs, perr := parseComposerJSONManifest(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "composer.json "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemPackagist, Kind: "composer.json (manifest fallback)"})
		case "pyproject.toml":
			if hasPythonLockSibling(path) {
				return nil // poetry.lock / uv.lock / pdm.lock wins
			}
			pkgs, perr := parsePyprojectManifest(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "pyproject.toml "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemPyPI, Kind: "pyproject.toml (manifest fallback)"})
		case ".gitlab-ci.yml", ".gitlab-ci.yaml":
			pkgs, perr := parseGitLabCI(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, ".gitlab-ci.yml "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemGitLabCI, Kind: ".gitlab-ci.yml"})
			appendDockerRefs(inv, path)
		case "bitbucket-pipelines.yml", "bitbucket-pipelines.yaml":
			pkgs, perr := parseBitbucketPipelines(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "bitbucket-pipelines.yml "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemBitbucketPipes, Kind: "bitbucket-pipelines.yml"})
			appendDockerRefs(inv, path)
		case "azure-pipelines.yml", "azure-pipelines.yaml":
			pkgs, perr := parseAzurePipelines(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "azure-pipelines.yml "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemAzurePipelines, Kind: "azure-pipelines.yml"})
			appendDockerRefs(inv, path)
		case "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml":
			pkgs, perr := parseDockerImageRefs(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "compose "+path+": "+perr.Error())
				return nil
			}
			if len(pkgs) > 0 {
				inv.Packages = append(inv.Packages, pkgs...)
				inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemDocker, Kind: "compose"})
			}
		}

		// MCP host-config files: dispatched after the main switch so
		// they don't collide with ambiguous basenames. v0.17.
		if IsKnownMCPConfig(base) || IsGeminiSettingsJSON(path) {
			pkgs, perr := parseMCPConfig(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "mcp "+path+": "+perr.Error())
				return nil
			}
			if len(pkgs) > 0 {
				inv.Packages = append(inv.Packages, pkgs...)
				kind := "mcp-config"
				if IsGeminiSettingsJSON(path) {
					kind = "gemini-settings"
				}
				inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemMCP, Kind: kind})
			}
		}

		slashed := filepath.ToSlash(path)

		// GitHub & Gitea Actions workflows
		isGHWorkflow := strings.Contains(slashed, "/.github/workflows/") ||
			strings.HasPrefix(slashed, ".github/workflows/")
		isGiteaWorkflow := strings.Contains(slashed, "/.gitea/workflows/") ||
			strings.HasPrefix(slashed, ".gitea/workflows/")
		if (isGHWorkflow || isGiteaWorkflow) &&
			(strings.HasSuffix(slashed, ".yml") || strings.HasSuffix(slashed, ".yaml")) {
			pkgs, perr := parseGHActionsWorkflow(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "workflow "+path+": "+perr.Error())
				return nil
			}
			kind := "workflow"
			if isGiteaWorkflow {
				kind = "gitea-workflow"
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemActions, Kind: kind})
			appendDockerRefs(inv, path)
		}

		// CircleCI config
		if strings.HasSuffix(slashed, "/.circleci/config.yml") ||
			strings.HasSuffix(slashed, "/.circleci/config.yaml") ||
			slashed == ".circleci/config.yml" ||
			slashed == ".circleci/config.yaml" {
			pkgs, perr := parseCircleCIConfig(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "circleci config "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemCircleCIOrbs, Kind: ".circleci/config.yml"})
			appendDockerRefs(inv, path)
		}

		// Azure Pipelines subdirectory layout
		if (strings.Contains(slashed, "/.azure-pipelines/") || strings.HasPrefix(slashed, ".azure-pipelines/")) &&
			(strings.HasSuffix(slashed, ".yml") || strings.HasSuffix(slashed, ".yaml")) {
			pkgs, perr := parseAzurePipelines(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "azure-pipelines "+path+": "+perr.Error())
				return nil
			}
			inv.Packages = append(inv.Packages, pkgs...)
			inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemAzurePipelines, Kind: "azure-pipelines"})
			appendDockerRefs(inv, path)
		}

		// Dockerfile + variants (Dockerfile.dev, Dockerfile.prod, …)
		if base == "Dockerfile" || base == "dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
			pkgs, perr := parseDockerfile(path)
			if perr != nil {
				inv.Errors = append(inv.Errors, "Dockerfile "+path+": "+perr.Error())
				return nil
			}
			if len(pkgs) > 0 {
				inv.Packages = append(inv.Packages, pkgs...)
				inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemDocker, Kind: "Dockerfile"})
			}
		}
		return nil
	})
	if err != nil {
		return inv, err
	}
	return inv, nil
}

// appendDockerRefs scans a CI YAML for `image:` keys and appends every
// discovered Docker image reference to the inventory. No-op if the file has
// no image references; errors get captured in inv.Errors.
func appendDockerRefs(inv *Inventory, path string) {
	pkgs, err := parseDockerImageRefs(path)
	if err != nil {
		inv.Errors = append(inv.Errors, "docker image refs "+path+": "+err.Error())
		return
	}
	if len(pkgs) == 0 {
		return
	}
	inv.Packages = append(inv.Packages, pkgs...)
	inv.Sources = append(inv.Sources, Source{Path: path, Ecosystem: EcosystemDocker, Kind: "image-refs"})
}
