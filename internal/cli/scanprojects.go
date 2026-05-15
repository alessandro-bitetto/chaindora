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
	"github.com/alessandro-bitetto/chaindora/internal/progress"
)

// projectScanOpts configures scanProject's detector pipeline.
type projectScanOpts struct {
	IncidentsDir  string
	SkipOSV       bool
	SkipIncidents bool
	SkipHeuristic bool
	FreshPopular  bool
	Verbose       bool
	Excludes      []string
	// PreInventory, if non-nil, bypasses inventory.Scan and runs the detector
	// pipeline against the supplied Inventory directly. Used by deep-mode
	// (`chdora forensics --deep`) where the inventory comes from
	// `npm ls -g` / `pip list` rather than a filesystem walk.
	PreInventory *inventory.Inventory
}

// scanProject runs the full chdora scan pipeline against a single project
// root and returns the aggregated findings. Returns nil for an empty inventory
// (no project markers actually parseable at that root).
func scanProject(ctx context.Context, root string, opts projectScanOpts) ([]findings.Finding, error) {
	var inv *inventory.Inventory
	if opts.PreInventory != nil {
		inv = opts.PreInventory
	} else {
		var err error
		inv, err = inventory.Scan(root, inventory.WithExcludes(opts.Excludes...))
		if err != nil {
			return nil, err
		}
	}
	if len(inv.Packages) == 0 && len(inv.Sources) == 0 {
		return nil, nil
	}
	if opts.Verbose {
		label := root
		if opts.PreInventory != nil {
			label = "--deep (global packages)"
		}
		fmt.Fprintf(os.Stderr, "  %s: %d pkgs / %d sources\n", label, len(inv.Packages), len(inv.Sources))
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
				det := incident.New(incs, opts.Excludes...)
				if results, err := det.Detect(ctx, inv, root); err == nil {
					all = append(all, results...)
				}
			}
		}
	}
	if !opts.SkipHeuristic {
		det := heuristic.New(heuristic.Config{
			FreshPopular: heuristic.FreshPopularConfig{Enabled: opts.FreshPopular},
			Excludes:     opts.Excludes,
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

// mergeExcludeMap merges user-supplied directory names into the default skip
// set so discoverProjects honors both.
func mergeExcludeMap(userExcludes []string) map[string]bool {
	out := make(map[string]bool, len(defaultScanProjectsSkipDirs)+len(userExcludes))
	for k, v := range defaultScanProjectsSkipDirs {
		out[k] = v
	}
	for _, e := range userExcludes {
		if e != "" {
			out[e] = true
		}
	}
	return out
}

// discoverProjects walks root looking for files that mark a project root,
// returning the deduplicated, ancestor-preferred list of containing
// directories. If a discovered directory is a sub-directory of another that's
// also discovered, only the ancestor is kept (one inventory.Scan() against
// the ancestor will subsume the nested manifests).
func discoverProjects(root string, skip map[string]bool) []string {
	found := map[string]struct{}{}
	prog := progress.New(os.Stderr)
	prog.Start(fmt.Sprintf("discovering projects under %s", root))
	defer func() {
		prog.Stop(fmt.Sprintf("[chdora] discovered %d candidate project root(s) under %s", len(found), root))
	}()
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		prog.Tick()
		if d.IsDir() {
			if path == root {
				return nil
			}
			// Default skip list lives in inventory.ShouldSkipDir
			// (shared with the inventory parser + incident artifact
			// walker). `skip` carries user-supplied --exclude
			// basenames on top.
			if inventory.ShouldSkipDir(path, d.Name()) {
				return filepath.SkipDir
			}
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			// CI-config directories that mark their parent as a project
			// even when no root-level manifest exists.
			switch d.Name() {
			case ".circleci", ".azure-pipelines":
				found[filepath.Dir(path)] = struct{}{}
				prog.Hit()
			case "workflows":
				parent := filepath.Dir(path)
				base := filepath.Base(parent)
				if base == ".github" || base == ".gitea" {
					found[filepath.Dir(parent)] = struct{}{}
					prog.Hit()
				}
			}
			return nil
		}
		if isProjectMarker(d.Name()) {
			if _, dup := found[filepath.Dir(path)]; !dup {
				prog.Hit()
			}
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
