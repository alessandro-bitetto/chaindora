package inventory

import (
	"path/filepath"
	"strings"
)

// ShouldSkipDir reports whether a directory at the given absolute path,
// with the given basename, should be skipped during any scan walk.
// Centralizes the conventional skip list across the inventory parser,
// the project-discovery walker (chdora forensics --scan-projects), and
// the incident-pack file-artifact walker. These directories are
// caches, build outputs, virtual environments, IDE / package-manager
// internals, or platform-level user data that don't contain
// user-actionable supply-chain content.
//
// path is required only for the Go module cache check ($GOPATH/pkg/mod):
// the basename "mod" alone is too generic to skip safely, but "mod
// whose parent is pkg" reliably matches Go's GOMODCACHE convention
// without over-matching legitimate directories named "mod" elsewhere.
func ShouldSkipDir(path, name string) bool {
	// Renamed / extracted dependency trees. Container volumes and some
	// tooling mount node_modules under a non-literal basename
	// (mvp_be_node_modules, fe_node_modules, ...); the bytes are still a
	// third-party install the user can't edit in place. Matching the
	// "node_modules" suffix catches both the literal dir and the renamed
	// variants that the basename list below would miss — which is exactly
	// how a Docker volume's vendored modules slipped into an audit walk.
	if strings.HasSuffix(name, "node_modules") {
		return true
	}
	switch name {
	case
		// Package-manager / build-output trees holding third-party
		// code copies the user can't edit in place.
		".venv", "venv", "__pycache__",
		"vendor", "target", "dist", "build", ".next",
		".gradle", ".cache", ".npm", ".yarn", ".pnpm-store",
		".terraform", ".m2", ".gem", ".rustup", ".cargo", ".go",
		// Container / VM product data: OrbStack, Colima, Docker. These
		// hold the disk images and named volumes of containers the user
		// runs — third-party install trees that aren't remediated in
		// place (you rebuild the image or fix the source repo, not the
		// runtime volume sitting on the laptop). Same scoping rationale
		// as node_modules / Library: real risk, but it belongs to the
		// image, surfaced when its source repo is scanned — not here.
		"OrbStack", ".orbstack", ".colima", ".docker", "DockerDesktop",
		// Version control.
		".git",
		// OS-level user-data dirs whose contents are managed by the
		// OS or third parties, not by the user-as-developer.
		"Library", "AppData",
		// Go convention: testdata holds fixture inputs, often
		// intentionally malformed or vulnerable for test cases.
		// Skipping prevents both a project from finding its own
		// fixtures AND a $HOME-walking forensics run from finding
		// chdora's own test fixtures (which by design look exactly
		// like real malicious code).
		"testdata",
		// IDE extension storage. Each extension ships its own
		// package-lock.json with its own dependency CVEs, but those
		// are the extension author's problem — the user can't
		// commit a fix to someone else's extension.
		".vscode", ".cursor",
		// Homebrew internal storage. Per-formula versioned
		// resources live here; users upgrade via `brew upgrade`,
		// not by editing lockfiles inside Cellar.
		"Cellar":
		return true
	case "mod":
		// Go module cache: $GOPATH/pkg/mod. Read-only, content-
		// addressed. Findings inside aren't actionable because the
		// user resolves them via go.mod, not by editing the cache.
		return filepath.Base(filepath.Dir(path)) == "pkg"
	}
	// Linux Docker storage driver root (basename varies: overlay2,
	// volumes, containers, image, ...), matched by path so we don't
	// over-skip a source dir that merely happens to be named "volumes".
	if strings.Contains(filepath.ToSlash(path), "/var/lib/docker/") {
		return true
	}
	return false
}
