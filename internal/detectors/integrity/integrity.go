// Package integrity verifies that on-disk lockfile hashes match
// what the upstream registry signed for. Catches the case where
// a module was MITM-swapped between resolution and storage —
// the gate's preflight checks "is this satisfied," but doesn't
// check "is what's on disk what we think it is."
//
// Two ecosystems for v0.13.1:
//   - Go modules: go.sum entries vs sum.golang.org's transparency
//     log. If they disagree, the local copy has been tampered
//     with OR the user's GOSUMDB is misconfigured.
//   - Rust crates: Cargo.lock has per-package checksums. We
//     verify each against the corresponding crates.io index
//     entry.
//
// Findings are CategoryHostForensics with VulnID
// INTEGRITY-MISMATCH — they indicate a host or supply-chain
// integrity issue, not a vulnerability in the package itself.
package integrity

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

// Detector emits integrity findings for go.sum and Cargo.lock
// files discovered under ProjectRoots.
type Detector struct {
	ProjectRoots []string
	GoProbe      *registries.GoMod
	HTTPClient   *http.Client
}

// New returns a Detector scanning the supplied project roots.
// If roots is empty, the caller is expected to populate before
// calling Detect.
func New(roots []string) *Detector {
	return &Detector{
		ProjectRoots: roots,
		GoProbe:      registries.NewGoMod(),
		HTTPClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Detect walks every root looking for go.sum and Cargo.lock,
// then cross-references hashes. The check is intentionally
// passive: we don't recompute hashes from on-disk module
// contents (that's `go mod verify` / `cargo verify-project`
// territory). What we DO is cross-check the LOCKFILE-RECORDED
// hash against the REGISTRY-PUBLISHED hash. A mismatch means
// the lockfile was tampered with.
func (d *Detector) Detect(ctx context.Context) ([]findings.Finding, error) {
	var out []findings.Finding
	for _, root := range d.ProjectRoots {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			base := filepath.Base(path)
			switch base {
			case "go.sum":
				fs := d.checkGoSum(ctx, path)
				out = append(out, fs...)
				// v0.15: also do lockfile-vs-disk for go modules.
				out = append(out, d.checkGoModulesLockfileVsDisk(ctx, path)...)
			case "Cargo.lock":
				// v0.15: lockfile-vs-disk drift check for cargo.
				// Cross-references Cargo.lock against
				// ~/.cargo/registry/src/.
				out = append(out, d.checkCargoLockfileVsDisk(ctx, path)...)
			case "Pipfile.lock":
				// v0.15: lockfile-vs-disk drift check for pip.
				// Compares Pipfile.lock against the project's
				// .venv/lib/python*/site-packages METADATA.
				out = append(out, d.checkPipLockfileVsDisk(ctx, path)...)
			case "package-lock.json":
				// v0.15: lockfile-vs-disk check for npm — compare
				// what's pinned in package-lock.json to what's
				// actually under node_modules/. Catches post-install
				// tampering by a malicious dependency, a worm
				// artifact, or a manual edit by an attacker with
				// file-level access.
				fs := d.checkNPMLockfileVsDisk(ctx, path)
				out = append(out, fs...)
			case "yarn.lock":
				fs := d.checkYarnLockfileVsDisk(ctx, path)
				out = append(out, fs...)
			case "pnpm-lock.yaml":
				fs := d.checkPnpmLockfileVsDisk(ctx, path)
				out = append(out, fs...)
			}
			return nil
		})
	}
	return out, nil
}

// checkGoSum reads a go.sum file and, for each module@version
// entry, looks up the same entry in sum.golang.org. The sum
// in sumdb is the canonical "what the Go team's transparency
// log says this version's hash is." If the local sum
// disagrees, the local file has been tampered with.
//
// We don't try to parse the signed-note format; we just compare
// hash strings, which is what `go mod verify` effectively does
// under the hood.
func (d *Detector) checkGoSum(ctx context.Context, path string) []findings.Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []findings.Finding
	// Bound the number of sumdb lookups per file. A monorepo
	// with 1000-entry go.sum could DOS sum.golang.org if we
	// unconditionally hit every line. 100 entries = first 100
	// modules in the file; users can rerun for full coverage.
	checked := 0
	const maxChecks = 100
	seen := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// Format: "<module> <version> h1:<base64>="
		// or:     "<module> <version>/go.mod h1:<base64>="
		// We want the module-zip lines (no /go.mod suffix), which
		// hash the actual source.
		parts := strings.SplitN(line, " ", 3)
		if len(parts) != 3 {
			continue
		}
		mod := parts[0]
		ver := parts[1]
		if strings.HasSuffix(ver, "/go.mod") {
			continue
		}
		localHash := parts[2]
		key := mod + "@" + ver
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		if checked >= maxChecks {
			break
		}
		checked++
		upstream, err := d.fetchSumDBHash(ctx, mod, ver)
		if err != nil || upstream == "" {
			continue
		}
		if upstream != localHash {
			out = append(out, findings.Finding{
				Detector:   "integrity:gosum",
				Category:   findings.CategoryHostForensics,
				VulnID:     "INTEGRITY-MISMATCH",
				Summary:    fmt.Sprintf("go.sum hash for %s@%s disagrees with sum.golang.org — local lockfile may have been tampered with", mod, ver),
				Severity:   findings.SeverityHigh,
				SourcePath: path,
				References: []string{
					fmt.Sprintf("https://sum.golang.org/lookup/%s@%s", mod, ver),
				},
			})
		}
	}
	return out
}

// fetchSumDBHash queries sum.golang.org/lookup/<mod>@<ver>.
// Response body is a multi-line text format:
//
//	<id>
//	<mod> <ver> h1:<hash>=
//	<mod> <ver>/go.mod h1:<hash>=
//
// We extract the h1: line that matches the module ZIP (no
// /go.mod suffix).
func (d *Detector) fetchSumDBHash(ctx context.Context, mod, ver string) (string, error) {
	url := fmt.Sprintf("https://sum.golang.org/lookup/%s@%s",
		goModEscape(mod), ver)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, " ", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] != mod {
			continue
		}
		if strings.HasSuffix(parts[1], "/go.mod") {
			continue
		}
		return parts[2], nil
	}
	return "", nil
}

// goModEscape replicates the GOPROXY case-escape rule. Kept
// here as a local copy to avoid a hard registries dep on the
// detector.
func goModEscape(module string) string {
	var b strings.Builder
	for _, r := range module {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
