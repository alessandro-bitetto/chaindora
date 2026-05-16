package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Two ecosystems don't carry per-package content hashes in their
// standard resolver output: bundler (Gemfile.lock has no per-gem
// checksum field — Bundler 2.6+ added an optional CHECKSUMS
// section but it's not universally adopted) and Maven (Maven's
// dependency:list output has no hashes; the .jar artifacts have
// sibling .sha1 / .sha256 files in the registry).
//
// For the verdict cache + republish-guard to cover these
// ecosystems, the resolver fetches the integrity hash from the
// registry after parsing the lockfile / dep list. Failures (timeout,
// 404, transient registry hiccup) leave Integrity empty — the gate
// degrades gracefully to "no republish-guard coverage for this
// package this run" instead of failing the install.

// integrityHTTPClient is a small shared HTTP client used by the
// per-ecosystem fetchers. Short timeout + connection reuse keeps
// the parallel fan-out tight.
var integrityHTTPClient = &http.Client{
	Timeout: 8 * time.Second,
}

// enrichRubyGemsIntegrity fetches the published sha256 for each
// gem ref via rubygems.org's API and stuffs it into Integrity.
// Modifies refs in place; returns the same slice for convenience.
//
// API: GET https://rubygems.org/api/v2/rubygems/<name>/versions/<version>.json
// Response includes a `sha` field with the .gem file's sha256.
func enrichRubyGemsIntegrity(ctx context.Context, refs []PackageRef) []PackageRef {
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentChecks)
	for i := range refs {
		if refs[i].Ecosystem != "rubygems" || refs[i].Integrity != "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			if h := fetchRubyGemSHA(ctx, refs[idx].Name, refs[idx].Version); h != "" {
				refs[idx].Integrity = h
			}
		}(i)
	}
	wg.Wait()
	return refs
}

func fetchRubyGemSHA(ctx context.Context, name, version string) string {
	u := fmt.Sprintf("https://rubygems.org/api/v2/rubygems/%s/versions/%s.json",
		url.PathEscape(name), url.PathEscape(version))
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "chdora-gate-integrity")
	resp, err := integrityHTTPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var body struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		return ""
	}
	if body.SHA == "" {
		return ""
	}
	return "sha256:" + body.SHA
}

// enrichMavenIntegrity fetches the .sha256 (or .sha1 as fallback)
// for each artifact from repo1.maven.org and stuffs it into
// Integrity. PackageRef.Name is "group:artifact" per the maven
// resolver; we split on the colon to form the Central path.
//
// Tries the .jar artifact's checksum first; falls through to .pom
// for parent-pom-only entries. If both 404 (rare extension like
// .aar / .war), Integrity stays empty.
func enrichMavenIntegrity(ctx context.Context, refs []PackageRef) []PackageRef {
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentChecks)
	for i := range refs {
		if refs[i].Ecosystem != "maven" || refs[i].Integrity != "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			if h := fetchMavenSHA(ctx, refs[idx].Name, refs[idx].Version); h != "" {
				refs[idx].Integrity = h
			}
		}(i)
	}
	wg.Wait()
	return refs
}

func fetchMavenSHA(ctx context.Context, fullName, version string) string {
	colon := strings.Index(fullName, ":")
	if colon <= 0 || colon == len(fullName)-1 {
		return ""
	}
	group, artifact := fullName[:colon], fullName[colon+1:]
	groupPath := strings.ReplaceAll(group, ".", "/")
	// Maven Central guarantees .sha1 for every artifact; .sha256
	// exists for some new uploads but is far from universal (seen
	// ~10–20% coverage in practice as of 2026). Try .sha1 first
	// to skip the wasted round-trip on the common case. Pom-only
	// entries (parent BOMs) fall through to the .pom path. SHA1
	// is fine here: republish detection needs preimage resistance,
	// not collision resistance — the attacker would have to craft
	// a payload that hashes to the SAME sha1 as the original, which
	// remains computationally infeasible.
	candidates := []struct{ ext, alg string }{
		{"jar.sha1", "sha1"},
		{"pom.sha1", "sha1"},
	}
	for _, c := range candidates {
		u := fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.%s",
			groupPath, artifact, version, artifact, version, c.ext)
		if h := fetchMavenHashBody(ctx, u); h != "" {
			return c.alg + ":" + h
		}
	}
	return ""
}

func fetchMavenHashBody(ctx context.Context, u string) string {
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "chdora-gate-integrity")
	resp, err := integrityHTTPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	// Checksum files are tiny — 40-64 hex chars, sometimes followed
	// by whitespace and a filename ("abc...  artifact.jar").
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(body))
	if len(fields) == 0 {
		return ""
	}
	h := strings.ToLower(strings.TrimSpace(fields[0]))
	// Validate hex; reject empty / non-hex bodies (a wrong Content-
	// Type or HTML error page would otherwise sneak through).
	if h == "" || !isHex(h) {
		return ""
	}
	return h
}
