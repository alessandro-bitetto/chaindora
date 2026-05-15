package cli

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/detectors/heuristic"
	"github.com/alessandro-bitetto/chaindora/internal/detectors/incident"
	"github.com/alessandro-bitetto/chaindora/internal/detectors/osvioc"
	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/incidents"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
	"github.com/alessandro-bitetto/chaindora/internal/osv"
)

// projectScanOpts configures scanProject's detector pipeline.
type projectScanOpts struct {
	IncidentsDir  string
	SkipOSV       bool
	SkipIncidents bool
	SkipHeuristic bool
	FreshPopular  bool
	Verbose       bool
}

// scanProject runs the full chaindora scan pipeline against a single project
// root and returns the aggregated findings. Returns nil for an empty inventory
// (no project markers actually parseable at that root).
func scanProject(ctx context.Context, root string, opts projectScanOpts) ([]findings.Finding, error) {
	inv, err := inventory.Scan(root)
	if err != nil {
		return nil, err
	}
	if len(inv.Packages) == 0 && len(inv.Sources) == 0 {
		return nil, nil
	}
	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "  %s: %d pkgs / %d sources\n", root, len(inv.Packages), len(inv.Sources))
	}

	var all []findings.Finding
	if !opts.SkipOSV {
		det := osvioc.New(osv.NewClient())
		if results, err := det.Detect(ctx, inv); err == nil {
			all = append(all, results...)
		}
	}
	if !opts.SkipIncidents {
		dir := incidents.ResolveDir([]string{
			opts.IncidentsDir,
			filepath.Join(os.Getenv("HOME"), ".chaindora", "incidents"),
			"incidents",
		})
		if dir != "" {
			if incs, err := incidents.LoadDir(dir); err == nil {
				det := incident.New(incs)
				if results, err := det.Detect(ctx, inv, root); err == nil {
					all = append(all, results...)
				}
			}
		}
	}
	if !opts.SkipHeuristic {
		det := heuristic.New(heuristic.Config{
			FreshPopular: heuristic.FreshPopularConfig{Enabled: opts.FreshPopular},
		})
		if results, err := det.Detect(ctx, inv, root); err == nil {
			all = append(all, results...)
		}
	}
	return all, nil
}

// projectMarkers names the files whose presence indicates a project root.
// Directories named .github/workflows etc. are handled separately so we don't
// trip every file inside them.
var projectMarkers = map[string]bool{
	"package.json":            true,
	"package-lock.json":       true,
	"yarn.lock":               true,
	"pnpm-lock.yaml":          true,
	"requirements.txt":        true,
	"pyproject.toml":          true,
	"Pipfile":                 true,
	"Pipfile.lock":            true,
	"poetry.lock":             true,
	"uv.lock":                 true,
	"Dockerfile":              true,
	"dockerfile":              true,
	"docker-compose.yml":      true,
	"docker-compose.yaml":     true,
	"compose.yml":             true,
	"compose.yaml":            true,
	"Cargo.toml":              true,
	"go.mod":                  true,
	"Gemfile":                 true,
	"pom.xml":                 true,
	"build.gradle":            true,
	"build.gradle.kts":        true,
	".gitlab-ci.yml":          true,
	".gitlab-ci.yaml":         true,
	"bitbucket-pipelines.yml": true,
	"bitbucket-pipelines.yaml": true,
	"azure-pipelines.yml":     true,
	"azure-pipelines.yaml":    true,
}

// defaultScanProjectsSkipDirs is the built-in list of directory names that
// scanProjects's walk refuses to descend into. These are caches, build
// outputs, virtual environments, and platform AppData — none of which contain
// the canonical project manifests we're looking for, and all of which can
// contain enormous numbers of files.
var defaultScanProjectsSkipDirs = map[string]bool{
	"node_modules": true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	".git":         true,
	"vendor":       true,
	"target":       true,
	".next":        true,
	"dist":         true,
	"build":        true,
	".gradle":      true,
	".cache":       true,
	".npm":         true,
	".yarn":        true,
	".pnpm-store":  true,
	".terraform":   true,
	"Library":      true, // macOS user library
	"AppData":      true, // Windows user data
	".m2":          true,
	".gem":         true,
	".rustup":      true,
	".cargo":       true,
	".go":          true,
}

func isProjectMarker(name string) bool {
	if projectMarkers[name] {
		return true
	}
	if strings.HasPrefix(name, "Dockerfile.") {
		return true
	}
	return false
}

// discoverProjects walks root looking for files that mark a project root,
// returning the deduplicated, ancestor-preferred list of containing
// directories. If a discovered directory is a sub-directory of another that's
// also discovered, only the ancestor is kept (one inventory.Scan() against
// the ancestor will subsume the nested manifests).
func discoverProjects(root string, skip map[string]bool) []string {
	if skip == nil {
		skip = defaultScanProjectsSkipDirs
	}
	found := map[string]struct{}{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			// CI-config directories that mark their parent as a project
			// even when no root-level manifest exists.
			switch d.Name() {
			case ".circleci", ".azure-pipelines":
				found[filepath.Dir(path)] = struct{}{}
			case "workflows":
				parent := filepath.Dir(path)
				base := filepath.Base(parent)
				if base == ".github" || base == ".gitea" {
					found[filepath.Dir(parent)] = struct{}{}
				}
			}
			return nil
		}
		if isProjectMarker(d.Name()) {
			found[filepath.Dir(path)] = struct{}{}
		}
		return nil
	})
	roots := make([]string, 0, len(found))
	for r := range found {
		roots = append(roots, r)
	}
	sort.Strings(roots)
	return collapseNestedRoots(roots)
}

// collapseNestedRoots drops any directory that is a descendant of another
// directory already in the list. Input must be sorted.
func collapseNestedRoots(roots []string) []string {
	var out []string
	for _, r := range roots {
		nested := false
		for _, parent := range out {
			if r == parent {
				nested = true
				break
			}
			if strings.HasPrefix(r, parent+string(filepath.Separator)) {
				nested = true
				break
			}
		}
		if !nested {
			out = append(out, r)
		}
	}
	return out
}
