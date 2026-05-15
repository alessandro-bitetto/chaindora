package inventory

import "path/filepath"

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
	switch name {
	case
		// Package-manager / build-output trees holding third-party
		// code copies the user can't edit in place.
		"node_modules", ".venv", "venv", "__pycache__",
		"vendor", "target", "dist", "build", ".next",
		".gradle", ".cache", ".npm", ".yarn", ".pnpm-store",
		".terraform", ".m2", ".gem", ".rustup", ".cargo", ".go",
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
	return false
}
