package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// GitURLCheck evaluates "packages" sourced from a git URL rather
// than a registry. These are the worst-trust-model entries in
// the supply chain: no central registry, no signing, no
// provenance metadata. The only checks that apply are
// host-trust, ref-pinning, and transport-scheme.
//
// Triggered when a PackageRef has Ecosystem="git" and Version
// formatted as `<canonical-url>#<ref>`. The package-manager
// resolvers (resolve_npm.go etc.) emit this shape when they
// encounter a `git+https://...#sha` style entry in a lockfile.
//
// Verdict matrix:
//
//   well-known host + 40-hex SHA      → Approve (immutable + auditable)
//   well-known host + tag             → Warn (tags are mutable in theory)
//   well-known host + branch / HEAD   → Block (fully mutable)
//   unknown host  + 40-hex SHA      → Warn (you trust the bytes you saw, but no community oversight)
//   unknown host  + tag/branch       → Block
//   http://* or git://*               → Block (no transport security)
//
// All other gate checkers (cooldown, publisher-change, OSV,
// static-pattern, version-diff, maintainer-trust, provenance)
// return Approve passthrough for ecosystem="git" — they're
// registry-model checks that don't apply here.
type GitURLCheck struct {
	// AllowedHosts is the per-project allowlist of git hosts the
	// user trusts. Populated from chaindora.yml's
	// `allow.git_hosts` section. Always includes the well-
	// known hosts so users don't have to repeat them.
	AllowedHosts []string

	// AllowBranchRefs flips the "branch/HEAD = Block" rule to
	// Warn. Default false (strict). Useful in monorepos with
	// internal git URLs where ref-by-branch is the norm.
	AllowBranchRefs bool

	// MinRepoAge is the minimum age of a github.com repo we'll
	// approve without warning (zero = no check). 30 days
	// matches the v0.10 cooldown logic for npm packages: a
	// repo registered yesterday and immediately depended-on
	// is sleeper-pattern shape.
	MinRepoAge time.Duration

	// MinStars is the minimum stargazer count to approve a
	// github.com repo without warning (zero = no check). 5 is
	// the conservative default — picks up "real" projects
	// without false-positiving on personal-but-legitimate
	// repos with no marketing.
	MinStars int

	// GitHubAPI is the base URL for the GitHub REST API. Set
	// to "" to disable GitHub-specific enrichment (the
	// host-tier + ref-pin logic still works).
	GitHubAPI string

	// GitHubToken is an optional bearer for authenticated
	// requests (5000/hr rate limit instead of 60/hr).
	GitHubToken string

	// HTTPClient is the HTTP client used for GitHub API calls.
	HTTPClient *http.Client
}

// NewGitURLCheck returns a GitURLCheck with the default
// well-known hosts allowlist and reasonable thresholds. Reads
// GITHUB_TOKEN from the environment if set — same convention
// gh / hub / actions use.
func NewGitURLCheck() *GitURLCheck {
	return &GitURLCheck{
		MinRepoAge:  30 * 24 * time.Hour,
		MinStars:    5,
		GitHubAPI:   "https://api.github.com",
		GitHubToken: os.Getenv("GITHUB_TOKEN"),
		HTTPClient:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (g *GitURLCheck) Name() string { return "git-url" }

func (g *GitURLCheck) Check(ctx context.Context, ref PackageRef) CheckResult {
	r := CheckResult{Checker: g.Name()}
	if ref.Ecosystem != "git" {
		// Passthrough for non-git packages — every other
		// ecosystem already runs the registry-backed checkers.
		r.Verdict = VerdictApprove
		r.Reason = "git-url: passthrough for non-git ecosystem"
		return r
	}
	spec, ok := parseGitURLSpec(ref.Name, ref.Version)
	if !ok {
		r.Verdict = VerdictUnknown
		r.Reason = "git-url: could not parse URL or ref"
		return r
	}

	// Step 1: transport scheme. http and git:// are non-
	// starters because the bytes can be MITM'd in transit.
	if spec.Scheme == "http" || spec.Scheme == "git" {
		r.Verdict = VerdictBlock
		r.Reason = fmt.Sprintf("insecure transport %q — bytes can be tampered in transit", spec.Scheme)
		r.Detail = "Switch to https:// or ssh:// — git:// has no integrity check at all."
		return r
	}

	// Step 2: host tier.
	hostTier := classifyHost(spec.Host, g.AllowedHosts)

	// Step 3: ref pinning.
	refKind := classifyRef(spec.Ref)

	// Step 4: combine host-tier + ref-pin into a baseline
	// verdict. Then enrich with GitHub-API evidence when
	// possible to refine the call.
	baseline := classifyVerdict(refKind, hostTier, g.AllowBranchRefs, spec)
	r.Verdict = baseline.verdict
	r.Reason = baseline.reason

	// If we're approving a github.com repo, check whether the
	// repo itself looks legit. If we're blocking, GitHub API
	// won't rescue it. If we're warning, GitHub API can
	// either confirm the warn or downgrade to approve.
	if spec.Host == "github.com" && g.GitHubAPI != "" {
		meta := g.fetchGitHubMeta(ctx, spec)
		if meta != nil {
			if signal := g.evaluateGitHubMeta(meta); signal != "" {
				if r.Verdict == VerdictApprove {
					r.Verdict = VerdictWarn
				}
				r.Detail = signal
			}
		}
	}
	return r
}

// classifyVerdict returns the baseline verdict for a given
// (refKind, hostTier) combo. Split out so tests can target the
// pure logic without HTTP plumbing.
func classifyVerdict(refKind refKind, hostTier hostTier, allowBranch bool, spec gitURLSpec) struct {
	verdict Verdict
	reason  string
} {
	type result struct {
		verdict Verdict
		reason  string
	}
	switch {
	case refKind == refSHA && hostTier == hostTierWellKnown:
		return result{VerdictApprove, fmt.Sprintf("well-known host %s + pinned SHA %s", spec.Host, shortSHA(spec.Ref))}
	case refKind == refSHA && hostTier == hostTierAllowed:
		return result{VerdictApprove, fmt.Sprintf("allowlisted host %s + pinned SHA %s", spec.Host, shortSHA(spec.Ref))}
	case refKind == refSHA && hostTier == hostTierUnknown:
		return result{VerdictWarn, fmt.Sprintf("unknown host %s but ref is a pinned SHA — bytes are auditable, but community oversight is missing", spec.Host)}
	case refKind == refTag && hostTier == hostTierWellKnown:
		return result{VerdictWarn, fmt.Sprintf("well-known host %s + tag ref %q — tags are mutable in theory; prefer pinning to the underlying SHA", spec.Host, spec.Ref)}
	case refKind == refTag && hostTier != hostTierWellKnown:
		return result{VerdictBlock, fmt.Sprintf("non-well-known host %s + tag ref %q — combination is too easy to spoof", spec.Host, spec.Ref)}
	case refKind == refBranch && allowBranch:
		return result{VerdictWarn, fmt.Sprintf("branch ref %q at %s — attacker controlling the branch owns every future install", spec.Ref, spec.Host)}
	case refKind == refBranch:
		return result{VerdictBlock, fmt.Sprintf("branch ref %q is fully mutable — pin to a SHA or set allow.branch_refs: true in chaindora.yml if intentional", spec.Ref)}
	}
	return result{VerdictBlock, "git-url: no rule matched (treat as Block under fail-closed default)"}
}

// githubRepoMeta is the subset of /repos/<owner>/<repo> we use.
type githubRepoMeta struct {
	CreatedAt       time.Time `json:"created_at"`
	PushedAt        time.Time `json:"pushed_at"`
	StargazersCount int       `json:"stargazers_count"`
	Fork            bool      `json:"fork"`
	Archived        bool      `json:"archived"`
	Disabled        bool      `json:"disabled"`
	Private         bool      `json:"private"`
}

// fetchGitHubMeta does a single API call to /repos/<owner>/<repo>.
// Returns nil on network failure / 404 / 403 (rate-limited);
// the caller falls back to baseline verdict.
func (g *GitURLCheck) fetchGitHubMeta(ctx context.Context, spec gitURLSpec) *githubRepoMeta {
	owner, repo := parseGitHubOwnerRepo(spec.Path)
	if owner == "" || repo == "" {
		return nil
	}
	url := fmt.Sprintf("%s/repos/%s/%s",
		strings.TrimRight(g.GitHubAPI, "/"), owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if g.GitHubToken != "" {
		req.Header.Set("Authorization", "Bearer "+g.GitHubToken)
	}
	resp, err := g.HTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var meta githubRepoMeta
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&meta); err != nil {
		return nil
	}
	return &meta
}

// parseGitHubOwnerRepo strips a github.com URL path of leading
// "/" and trailing ".git", then splits "owner/repo".
func parseGitHubOwnerRepo(path string) (string, string) {
	p := strings.TrimPrefix(path, "/")
	p = strings.TrimSuffix(p, ".git")
	parts := strings.SplitN(p, "/", 3)
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// evaluateGitHubMeta returns a non-empty trust-signal string
// when the meta suggests something worth surfacing. Empty
// means "clean — keep the baseline verdict."
func (g *GitURLCheck) evaluateGitHubMeta(m *githubRepoMeta) string {
	if m == nil {
		return ""
	}
	var signals []string
	if m.Archived {
		signals = append(signals, "repo is ARCHIVED — pinning to an abandoned project is a maintenance risk")
	}
	if m.Disabled {
		signals = append(signals, "repo is DISABLED on GitHub")
	}
	if g.MinRepoAge > 0 && !m.CreatedAt.IsZero() {
		age := time.Since(m.CreatedAt)
		if age < g.MinRepoAge {
			signals = append(signals, fmt.Sprintf("repo created %s ago (< %s) — brand-new repo with no history",
				humanDuration(age), humanDuration(g.MinRepoAge)))
		}
	}
	if g.MinStars > 0 && m.StargazersCount < g.MinStars {
		signals = append(signals, fmt.Sprintf("only %d stargazer(s) — limited community vetting", m.StargazersCount))
	}
	if m.Fork {
		signals = append(signals, "repo is a fork — verify the fork hasn't been used to host malicious changes")
	}
	if len(signals) == 0 {
		return ""
	}
	return "GitHub-API trust signals:\n  - " + strings.Join(signals, "\n  - ")
}

// gitURLSpec is the parsed representation of a "name@version"
// pair where version is `<url>#<ref>`.
type gitURLSpec struct {
	Scheme string
	Host   string
	Path   string
	Ref    string // SHA, tag, or branch name
}

func parseGitURLSpec(_ string, version string) (gitURLSpec, bool) {
	// Strip the optional "git+" prefix npm uses.
	v := strings.TrimPrefix(version, "git+")
	// Split on '#' to separate URL from ref. Some lockfile
	// formats use a tab or other separators; we accept '#'
	// only for v0.11.1.
	hashIdx := strings.LastIndex(v, "#")
	if hashIdx < 0 {
		return gitURLSpec{}, false
	}
	rawURL := v[:hashIdx]
	ref := v[hashIdx+1:]
	if ref == "" {
		return gitURLSpec{}, false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return gitURLSpec{}, false
	}
	if u.Scheme == "" || u.Host == "" {
		return gitURLSpec{}, false
	}
	return gitURLSpec{
		Scheme: strings.ToLower(u.Scheme),
		Host:   strings.ToLower(u.Host),
		Path:   u.Path,
		Ref:    ref,
	}, true
}

type hostTier int

const (
	hostTierWellKnown hostTier = iota
	hostTierAllowed
	hostTierUnknown
)

// wellKnownHosts is chaindora's built-in trust list of major
// public git-hosting platforms. We don't try to be exhaustive
// — corporate / self-hosted instances go via the per-project
// allowlist in chaindora.yml.
var wellKnownHosts = map[string]bool{
	"github.com":    true,
	"gitlab.com":    true,
	"bitbucket.org": true,
	"codeberg.org":  true,
	"sr.ht":         true,
	"git.sr.ht":     true,
	"sourcehut.org": true,
}

func classifyHost(host string, allowed []string) hostTier {
	host = strings.ToLower(host)
	if wellKnownHosts[host] {
		return hostTierWellKnown
	}
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimSpace(a), host) {
			return hostTierAllowed
		}
	}
	return hostTierUnknown
}

type refKind int

const (
	refSHA refKind = iota
	refTag
	refBranch
)

// classifyRef heuristically determines what kind of git ref we
// have. Full 40-hex SHA → SHA. Looks like semver / starts with
// "v" → tag. Anything else → branch.
//
// "main", "master", "develop", "dev", "trunk" are the most
// common branch names and treated as obvious branches even
// though we could in theory tag with those names.
func classifyRef(ref string) refKind {
	r := strings.ToLower(strings.TrimSpace(ref))
	if len(r) == 40 && isHex(r) {
		return refSHA
	}
	// Short-SHA conventions (8-12 hex) are still pinned but
	// have a collision-attack surface. Treat as SHA.
	if (len(r) == 7 || len(r) == 8 || len(r) == 10 || len(r) == 12 || len(r) == 16) && isHex(r) {
		return refSHA
	}
	// Common branch names.
	for _, b := range []string{"main", "master", "develop", "dev", "trunk", "head"} {
		if r == b {
			return refBranch
		}
	}
	// Semver-ish or version-looking tag.
	if strings.HasPrefix(r, "v") && len(r) > 1 && isVersionish(r[1:]) {
		return refTag
	}
	if isVersionish(r) {
		return refTag
	}
	// Conservative default: anything else is a branch.
	return refBranch
}

func isHex(s string) bool {
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// isVersionish reports whether s looks like X.Y.Z or X.Y. We
// don't try to validate full semver — being permissive on
// what's a tag avoids treating "0.5-beta" or "1.0.0-rc.1" as
// a branch.
func isVersionish(s string) bool {
	if s == "" {
		return false
	}
	dots := 0
	hasDigit := false
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '.':
			dots++
		case c == '-' || c == '+':
			// Prerelease / build suffix — bail out, the prefix
			// before this point determined version-iness.
			return hasDigit && dots >= 1
		default:
			return false
		}
	}
	return hasDigit && dots >= 1
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}
