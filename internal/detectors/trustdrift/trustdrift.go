// Package trustdrift detects changes to the user's trust-anchor
// surfaces — the registry/index/repo overrides that would
// invalidate every other gate check if compromised.
//
// Model: baseline-and-diff. First run records hashes of every
// monitored file into ~/.chaindora/trustdrift-baseline.json. Each
// subsequent run computes current hashes and reports any
// difference. Per-file detectors also do CONTENT-AWARE warnings
// for high-risk shapes regardless of baseline state.
//
// We never modify the files. Findings surface as host-forensics
// findings the user can triage.
package trustdrift

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// Detector emits findings for trust-anchor changes.
type Detector struct {
	Home           string
	BaselinePath   string
	UpdateBaseline bool
}

// New returns a Detector rooted at home.
func New(home string) *Detector {
	return &Detector{
		Home:         home,
		BaselinePath: filepath.Join(home, ".chaindora", "trustdrift-baseline.json"),
	}
}

// Detect runs every monitored anchor through hash + content checks.
func (d *Detector) Detect(ctx context.Context) ([]findings.Finding, error) {
	baseline, err := loadBaseline(d.BaselinePath)
	if err != nil {
		return nil, err
	}
	current := map[string]string{}
	var out []findings.Finding

	anchors := d.anchorFiles()
	for _, a := range anchors {
		hash, exists, err := hashFile(a.path)
		if err != nil {
			continue
		}
		if exists {
			current[a.path] = hash
			if a.contentCheck != nil {
				out = append(out, a.contentCheck(a.path)...)
			}
		}
		if baseline != nil {
			priorHash, hadPrior := baseline.Hashes[a.path]
			switch {
			case exists && hadPrior && hash != priorHash:
				out = append(out, findings.Finding{
					Detector:   "hostforensics:trustdrift",
					Category:   findings.CategoryHostForensics,
					VulnID:     "TRUSTDRIFT-MODIFIED",
					Summary:    fmt.Sprintf("%s changed since baseline (%s)", a.label, baseline.CreatedAt),
					Severity:   findings.SeverityHigh,
					SourcePath: a.path,
				})
			case !exists && hadPrior:
				out = append(out, findings.Finding{
					Detector:   "hostforensics:trustdrift",
					Category:   findings.CategoryHostForensics,
					VulnID:     "TRUSTDRIFT-REMOVED",
					Summary:    fmt.Sprintf("%s removed since baseline (%s)", a.label, baseline.CreatedAt),
					Severity:   findings.SeverityMedium,
					SourcePath: a.path,
				})
			case exists && !hadPrior:
				out = append(out, findings.Finding{
					Detector:   "hostforensics:trustdrift",
					Category:   findings.CategoryHostForensics,
					VulnID:     "TRUSTDRIFT-ADDED",
					Summary:    fmt.Sprintf("%s appeared since baseline (%s)", a.label, baseline.CreatedAt),
					Severity:   findings.SeverityMedium,
					SourcePath: a.path,
				})
			}
		}
	}

	if baseline == nil || d.UpdateBaseline {
		if err := saveBaseline(d.BaselinePath, &baselineFile{
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
			Hashes:    current,
		}); err != nil {
			out = append(out, findings.Finding{
				Detector:   "hostforensics:trustdrift",
				Category:   findings.CategoryHostForensics,
				VulnID:     "TRUSTDRIFT-BASELINE-WRITE",
				Summary:    fmt.Sprintf("could not write trust-drift baseline: %v", err),
				Severity:   findings.SeverityLow,
				SourcePath: d.BaselinePath,
			})
		}
	}
	return out, nil
}

type anchor struct {
	path         string
	label        string
	contentCheck func(path string) []findings.Finding
}

func (d *Detector) anchorFiles() []anchor {
	home := d.Home
	anchors := []anchor{
		{filepath.Join(home, ".npmrc"), "~/.npmrc", checkNPMRC},
		{filepath.Join(home, ".pypirc"), "~/.pypirc", checkPyPIRC},
		{filepath.Join(home, ".pip", "pip.conf"), "~/.pip/pip.conf", checkPipConf},
		{filepath.Join(home, ".config", "pip", "pip.conf"), "~/.config/pip/pip.conf", checkPipConf},
		{filepath.Join(home, ".cargo", "config.toml"), "~/.cargo/config.toml", checkCargoConfig},
		{filepath.Join(home, ".cargo", "config"), "~/.cargo/config (legacy)", checkCargoConfig},
		{filepath.Join(home, ".gemrc"), "~/.gemrc", checkGemRC},
		{filepath.Join(home, ".m2", "settings.xml"), "~/.m2/settings.xml", checkMavenSettings},
		{filepath.Join(home, ".gradle", "init.gradle"), "~/.gradle/init.gradle", checkGradleInit},
		{filepath.Join(home, ".gradle", "init.gradle.kts"), "~/.gradle/init.gradle.kts", checkGradleInit},
		{filepath.Join(home, ".gitconfig"), "~/.gitconfig", checkGitConfig},
		{filepath.Join(home, ".ssh", "known_hosts"), "~/.ssh/known_hosts", nil},
		{filepath.Join(home, ".ssh", "config"), "~/.ssh/config", checkSSHConfig},
		// Sigstore trust roots: if an attacker can flip these,
		// every provenance verification afterwards is bypassed.
		{filepath.Join(home, ".sigstore", "root", "targets", "trusted_root.json"), "~/.sigstore/root/targets/trusted_root.json", nil},
		{filepath.Join(home, ".cosign", "cosign.pub"), "~/.cosign/cosign.pub", nil},
	}
	// Cross-platform system trust anchors: /etc/hosts and DNS
	// resolver config are the highest-impact host-level files
	// for supply-chain integrity. /etc/hosts overrides any DNS
	// resolution; /etc/resolv.conf points to which resolver
	// answers. Both have content-aware checks too.
	switch runtime.GOOS {
	case "darwin":
		anchors = append(anchors,
			anchor{"/etc/ssl/cert.pem", "macOS /etc/ssl/cert.pem", nil},
			anchor{"/etc/hosts", "/etc/hosts", checkEtcHosts},
			anchor{"/etc/resolv.conf", "/etc/resolv.conf", nil},
		)
	case "linux":
		anchors = append(anchors,
			anchor{"/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs/ca-certificates.crt", nil},
			anchor{"/etc/pki/tls/certs/ca-bundle.crt", "/etc/pki/tls/certs/ca-bundle.crt", nil},
			anchor{"/etc/hosts", "/etc/hosts", checkEtcHosts},
			anchor{"/etc/resolv.conf", "/etc/resolv.conf", nil},
		)
	}
	return anchors
}

// checkEtcHosts flags entries that redirect known package-
// registry hostnames anywhere other than their canonical
// addresses. The exact IP changes over time, so we don't pin
// IPs — we just flag the presence of an override that names
// a registry hostname. The user must confirm intentional
// (corporate mirror) vs unintentional (attacker MITM).
func checkEtcHosts(path string) []findings.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []findings.Finding
	suspicious := []string{
		"registry.npmjs.org",
		"pypi.org",
		"upload.pypi.org",
		"rubygems.org",
		"crates.io",
		"repo1.maven.org",
		"search.maven.org",
		"proxy.golang.org",
		"sum.golang.org",
		"github.com",
		"raw.githubusercontent.com",
		"codeload.github.com",
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// Each field after the IP is a hostname this line maps.
		for _, host := range fields[1:] {
			h := strings.ToLower(host)
			for _, s := range suspicious {
				if h == s || strings.HasSuffix(h, "."+s) {
					out = append(out, findings.Finding{
						Detector:   "hostforensics:trustdrift",
						Category:   findings.CategoryHostForensics,
						VulnID:     "TRUSTDRIFT-ETC-HOSTS",
						Summary:    fmt.Sprintf("/etc/hosts redirects %s to %s — verify intended (corp mirror or attacker MITM?)", host, fields[0]),
						Severity:   findings.SeverityHigh,
						SourcePath: path,
					})
					break
				}
			}
		}
	}
	return out
}

// checkMavenSettings flags settings.xml entries that route
// dependency resolution away from Maven Central. The XML is
// complex but we only care about <mirrors> and <repositories>
// — a substring check for hostnames in non-canonical positions
// suffices.
func checkMavenSettings(path string) []findings.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := string(data)
	if !strings.Contains(content, "<mirror>") && !strings.Contains(content, "<repository>") {
		return nil
	}
	// Heuristic: any <mirror> entry whose <url> isn't on Maven
	// Central or sonatype is suspicious-by-default.
	hasNonCanonicalMirror := strings.Contains(content, "<mirror>") &&
		!strings.Contains(content, "repo1.maven.org") &&
		!strings.Contains(content, "repo.maven.apache.org") &&
		!strings.Contains(content, "oss.sonatype.org")
	if !hasNonCanonicalMirror {
		return nil
	}
	return []findings.Finding{{
		Detector:   "hostforensics:trustdrift",
		Category:   findings.CategoryHostForensics,
		VulnID:     "TRUSTDRIFT-MAVEN-MIRROR",
		Summary:    "~/.m2/settings.xml has a <mirror> redirecting away from Maven Central — verify intended",
		Severity:   findings.SeverityMedium,
		SourcePath: path,
	}}
}

// checkGradleInit flags init.gradle files that override the
// default Maven repositories — same shape as Maven settings.xml.
func checkGradleInit(path string) []findings.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := string(data)
	if !strings.Contains(content, "repositories") && !strings.Contains(content, "maven {") {
		return nil
	}
	// Heuristic: init.gradle defining a custom maven{} block
	// without referencing mavenCentral() / google() is a
	// take-over-prone shape.
	if strings.Contains(content, "maven {") &&
		!strings.Contains(content, "mavenCentral()") &&
		!strings.Contains(content, "google()") &&
		!strings.Contains(content, "gradlePluginPortal()") {
		return []findings.Finding{{
			Detector:   "hostforensics:trustdrift",
			Category:   findings.CategoryHostForensics,
			VulnID:     "TRUSTDRIFT-GRADLE-REPO",
			Summary:    "~/.gradle/init.gradle defines a maven{} repository without mavenCentral()/google() — verify intended",
			Severity:   findings.SeverityMedium,
			SourcePath: path,
		}}
	}
	return nil
}

// checkSSHConfig flags `Host *` entries with `ProxyCommand`,
// `ProxyJump`, or `HostKeyAlgorithms` overrides — these can
// rewrite which server a git push lands at without the user
// noticing.
func checkSSHConfig(path string) []findings.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := string(data)
	for _, ind := range []string{"ProxyCommand", "ProxyJump"} {
		if strings.Contains(content, ind) {
			return []findings.Finding{{
				Detector:   "hostforensics:trustdrift",
				Category:   findings.CategoryHostForensics,
				VulnID:     "TRUSTDRIFT-SSH-PROXY",
				Summary:    fmt.Sprintf("~/.ssh/config contains %s — git operations route through a proxy, verify it's trusted", ind),
				Severity:   findings.SeverityMedium,
				SourcePath: path,
			}}
		}
	}
	return nil
}

func hashFile(path string) (string, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", true, err
	}
	return hex.EncodeToString(h.Sum(nil)), true, nil
}

type baselineFile struct {
	CreatedAt string            `json:"created_at"`
	Hashes    map[string]string `json:"hashes"`
}

func loadBaseline(path string) (*baselineFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var b baselineFile
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func saveBaseline(path string, b *baselineFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".trustdrift-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

func checkNPMRC(path string) []findings.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []findings.Finding
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if !strings.Contains(line, "registry=") {
			continue
		}
		idx := strings.Index(line, "registry=")
		val := strings.TrimSpace(line[idx+len("registry="):])
		val = strings.Trim(val, `"'`)
		if val == "" {
			continue
		}
		if !isCanonicalRegistry(val, "https://registry.npmjs.org") {
			sev := findings.SeverityMedium
			if strings.HasPrefix(val, "http://") {
				sev = findings.SeverityHigh
			}
			out = append(out, findings.Finding{
				Detector:   "hostforensics:trustdrift",
				Category:   findings.CategoryHostForensics,
				VulnID:     "TRUSTDRIFT-NPM-REGISTRY",
				Summary:    fmt.Sprintf(".npmrc redirects to %s (verify intended)", val),
				Severity:   sev,
				SourcePath: path,
			})
		}
	}
	return out
}

func checkPyPIRC(path string) []findings.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []findings.Finding
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, val := splitKV(line)
		if key != "repository" && key != "index-url" {
			continue
		}
		if val == "" {
			continue
		}
		if !isCanonicalRegistry(val, "https://upload.pypi.org/legacy/", "https://pypi.org/", "https://pypi.python.org/") {
			sev := findings.SeverityMedium
			if strings.HasPrefix(val, "http://") {
				sev = findings.SeverityHigh
			}
			out = append(out, findings.Finding{
				Detector:   "hostforensics:trustdrift",
				Category:   findings.CategoryHostForensics,
				VulnID:     "TRUSTDRIFT-PYPI-INDEX",
				Summary:    fmt.Sprintf(".pypirc redirects to %s (verify intended)", val),
				Severity:   sev,
				SourcePath: path,
			})
		}
	}
	return out
}

func checkPipConf(path string) []findings.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []findings.Finding
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, val := splitKV(line)
		if key != "index-url" && key != "extra-index-url" {
			continue
		}
		if val == "" {
			continue
		}
		if !isCanonicalRegistry(val, "https://pypi.org/simple", "https://pypi.python.org/simple") {
			sev := findings.SeverityMedium
			if strings.HasPrefix(val, "http://") {
				sev = findings.SeverityHigh
			}
			out = append(out, findings.Finding{
				Detector:   "hostforensics:trustdrift",
				Category:   findings.CategoryHostForensics,
				VulnID:     "TRUSTDRIFT-PIP-INDEX",
				Summary:    fmt.Sprintf("pip.conf %s = %s (verify intended)", key, val),
				Severity:   sev,
				SourcePath: path,
			})
		}
	}
	return out
}

func checkCargoConfig(path string) []findings.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []findings.Finding
	if strings.Contains(string(data), "replace-with") || strings.Contains(string(data), "[source.") {
		out = append(out, findings.Finding{
			Detector:   "hostforensics:trustdrift",
			Category:   findings.CategoryHostForensics,
			VulnID:     "TRUSTDRIFT-CARGO-SOURCE",
			Summary:    "~/.cargo/config has source-replacement rules — verify the replacement registry is trusted",
			Severity:   findings.SeverityMedium,
			SourcePath: path,
		})
	}
	return out
}

func checkGemRC(path string) []findings.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []findings.Finding
	content := string(data)
	if !strings.Contains(content, "rubygems.org") &&
		(strings.Contains(content, "sources:") || strings.Contains(content, "gem_sources")) {
		out = append(out, findings.Finding{
			Detector:   "hostforensics:trustdrift",
			Category:   findings.CategoryHostForensics,
			VulnID:     "TRUSTDRIFT-GEM-SOURCES",
			Summary:    "~/.gemrc sources don't reference rubygems.org — verify intended",
			Severity:   findings.SeverityMedium,
			SourcePath: path,
		})
	}
	return out
}

func checkGitConfig(path string) []findings.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := string(data)
	if !strings.Contains(content, "insteadOf") {
		return nil
	}
	return []findings.Finding{{
		Detector:   "hostforensics:trustdrift",
		Category:   findings.CategoryHostForensics,
		VulnID:     "TRUSTDRIFT-GIT-INSTEADOF",
		Summary:    "~/.gitconfig contains url.X.insteadOf rewrite — verify intended (an attacker with this line owns every git clone)",
		Severity:   findings.SeverityHigh,
		SourcePath: path,
	}}
}

func isCanonicalRegistry(u string, canonicals ...string) bool {
	uLower := strings.TrimRight(strings.ToLower(u), "/")
	for _, c := range canonicals {
		c = strings.TrimRight(strings.ToLower(c), "/")
		if strings.HasPrefix(uLower, c) {
			return true
		}
	}
	return false
}

func splitKV(line string) (key, val string) {
	for _, sep := range []string{"=", ":"} {
		if i := strings.Index(line, sep); i > 0 {
			return strings.TrimSpace(line[:i]), strings.Trim(strings.TrimSpace(line[i+1:]), `"'`)
		}
	}
	return "", ""
}
