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
