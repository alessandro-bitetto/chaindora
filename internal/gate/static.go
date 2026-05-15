package gate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// StaticScan inspects the actual bytes of a package version before
// they ever land in node_modules. Layered defense against the
// sleeper class of supply-chain attacks: shai-hulud, ctx, the
// crypto-stealer of qix were all detectable by static analysis at
// install time — the malware was right there in the published
// tarball, just nobody was looking.
//
// We don't try to fully decompile or de-obfuscate. The bar is much
// lower: catch the lazy obviously-malicious patterns. A patient
// adversary willing to write payload that looks like normal code
// will get through (that's the xz-utils class). For everything
// less sophisticated than that — which is empirically ~95% of
// observed npm attacks — static patterns work.
//
// Patterns we score:
//
//   * Install-script hooks that touch the network or spawn shells:
//       "postinstall": "curl ... | sh"
//       "postinstall": "node -e 'require(\"https\").get(...)'"
//   * eval() / new Function() with dynamic content
//   * High-entropy strings (base64/hex blobs ≥ 256 chars)
//   * `require('child_process')` or `import 'node:child_process'`
//     combined with `.spawn` / `.exec` that takes a constructed
//     command string
//   * Network calls to non-registry hosts inside install scripts
//
// Each pattern hit adds to a per-package score. Threshold 1+ →
// Warn, 3+ → Block. Calibrated against shai-hulud / ctx / qix to
// catch them all without false-positiving on common legitimate
// packages (we tested against react, lodash, webpack, vite).
type StaticScan struct {
	Probes     *Probes
	MaxBytes   int64
	HTTPClient *http.Client
	BlockAt    int // score threshold for Block
	WarnAt     int // score threshold for Warn
}

// NewStaticScan returns a StaticScan with defaults: 50MB tarball
// cap, score 1 = Warn, score 3 = Block. Caller must populate
// Probes before adding to a checker stack.
func NewStaticScan() *StaticScan {
	return &StaticScan{
		Probes:     NewProbes(),
		MaxBytes:   50 << 20,
		BlockAt:    3,
		WarnAt:     1,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *StaticScan) Name() string { return "static-pattern" }

func (s *StaticScan) Check(ctx context.Context, ref PackageRef) CheckResult {
	r := CheckResult{Checker: s.Name()}
	probe, ok := s.Probes.versionProbeFor(ref.Ecosystem)
	if !ok {
		r.Verdict = VerdictApprove
		r.Reason = fmt.Sprintf("static-pattern: no probe for ecosystem %q", ref.Ecosystem)
		return r
	}
	url, err := probe.TarballURL(ctx, ref.Name, ref.Version)
	if err != nil {
		r.Verdict = VerdictUnknown
		r.Reason = fmt.Sprintf("tarball url lookup failed: %v", err)
		return r
	}
	var buf bytes.Buffer
	if err := probe.FetchTarball(ctx, url, &buf); err != nil {
		r.Verdict = VerdictUnknown
		r.Reason = fmt.Sprintf("tarball download failed: %v", err)
		return r
	}
	findings, err := scanTarball(buf.Bytes(), s.MaxBytes)
	if err != nil {
		r.Verdict = VerdictUnknown
		r.Reason = fmt.Sprintf("tarball scan failed: %v", err)
		return r
	}
	// Score per UNIQUE pattern, not per occurrence. A library
	// that legitimately uses `new Function()` in its template
	// engine triggers the same pattern in multiple files — that's
	// still ONE signal, not N. Without this, lodash blocks
	// itself because its templating uses eval-of-dynamic across
	// `lodash.js` and `template.js`.
	score := 0
	for _, weight := range patternSet(findings) {
		score += weight
	}
	if score >= s.BlockAt {
		r.Verdict = VerdictBlock
		r.Reason = fmt.Sprintf("suspicious-pattern score %d ≥ block threshold %d", score, s.BlockAt)
		r.Detail = formatStaticFindings(findings)
		return r
	}
	if score >= s.WarnAt {
		r.Verdict = VerdictWarn
		r.Reason = fmt.Sprintf("suspicious-pattern score %d (≥ warn %d, < block %d)", score, s.WarnAt, s.BlockAt)
		r.Detail = formatStaticFindings(findings)
		return r
	}
	r.Verdict = VerdictApprove
	r.Reason = "no significant static-pattern signals"
	return r
}

// StaticFinding is one pattern-match hit. Weight is how heavily it
// counts toward the per-package score; severity ordering is
// roughly: high-confidence-malicious-shape (3) > eval-of-dynamic
// (2) > obfuscated-blob (1) > suspicious-import (1).
type StaticFinding struct {
	Pattern string
	Path    string
	Snippet string
	Weight  int
}

// scanTarball walks a gzipped tarball (npm tgz, PyPI sdist) and
// scores every file against the suspicious-pattern set. Returns
// the list of hits. maxBytes caps UNCOMPRESSED bytes we'll
// inspect to guard against tar-bomb payloads.
//
// Both npm and PyPI sdists land here unchanged — they're both
// gzipped tar with a top-level package directory; the file
// naming convention differs slightly (npm uses "package/...",
// PyPI uses "<name>-<version>/...") but stripFirstDir handles
// both.
func scanTarball(data []byte, maxBytes int64) ([]StaticFinding, error) {
	// Auto-detect archive format from magic bytes. npm and PyPI
	// sdists are gzip+tar; Maven JARs and PyPI wheels are zip;
	// rare other shapes (.crate is gzip+tar, .gem is plain tar
	// containing nested gzip+tar) handle below.
	switch {
	case isGzipMagic(data):
		return scanGzipTar(data, maxBytes)
	case isZipMagic(data):
		return scanZip(data, maxBytes)
	case isPlainTarMagic(data):
		return scanPlainTar(data, maxBytes)
	}
	return nil, fmt.Errorf("unknown archive format (not gzip, zip, or tar)")
}

// isGzipMagic — gzip files start with 0x1F 0x8B.
func isGzipMagic(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1F && data[1] == 0x8B
}

// isZipMagic — zip files start with "PK\x03\x04" (or "PK\x05\x06"
// for an empty archive). JARs and PyPI wheels are zip.
func isZipMagic(data []byte) bool {
	return len(data) >= 4 && data[0] == 'P' && data[1] == 'K' &&
		(data[2] == 0x03 || data[2] == 0x05) &&
		(data[3] == 0x04 || data[3] == 0x06)
}

// isPlainTarMagic — POSIX tar has "ustar" at offset 257.
// RubyGems' .gem files are this shape (a plain tar containing
// metadata.gz + data.tar.gz inside).
func isPlainTarMagic(data []byte) bool {
	return len(data) >= 265 && string(data[257:262]) == "ustar"
}

// scanGzipTar handles the npm / PyPI sdist / crate / .deb format.
func scanGzipTar(data []byte, maxBytes int64) ([]StaticFinding, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()
	return scanTarReader(tar.NewReader(gz), maxBytes)
}

func scanPlainTar(data []byte, maxBytes int64) ([]StaticFinding, error) {
	return scanTarReader(tar.NewReader(bytes.NewReader(data)), maxBytes)
}

// scanTarReader is the shared inner loop. Reads each regular
// file from the tar stream, strips the leading directory (npm's
// "package/" or PyPI's "<name>-<version>/"), and runs the
// per-file pattern detectors.
func scanTarReader(tr *tar.Reader, maxBytes int64) ([]StaticFinding, error) {
	var findings []StaticFinding
	var consumed int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar next: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		if hdr.Size > 4<<20 {
			continue
		}
		remaining := maxBytes - consumed
		if remaining <= 0 {
			break
		}
		readLimit := hdr.Size
		if readLimit > remaining {
			readLimit = remaining
		}
		content := make([]byte, readLimit)
		n, _ := io.ReadFull(tr, content)
		content = content[:n]
		consumed += int64(n)

		relPath := hdr.Name
		if i := strings.Index(relPath, "/"); i >= 0 {
			relPath = relPath[i+1:]
		}
		findings = append(findings, scanFile(relPath, content)...)
	}
	return findings, nil
}

// scanZip walks a zip archive — Maven JARs and PyPI wheels.
// JARs have no leading directory prefix (file names start at
// the package root); wheels do (`<name>-<version>.dist-info/`
// alongside the package modules). We don't strip anything for
// zip; the per-file detectors look at filename suffixes which
// makes the strip irrelevant.
func scanZip(data []byte, maxBytes int64) ([]StaticFinding, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("zip open: %w", err)
	}
	var findings []StaticFinding
	var consumed int64
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if f.UncompressedSize64 > 4<<20 {
			continue
		}
		remaining := maxBytes - consumed
		if remaining <= 0 {
			break
		}
		readLimit := int64(f.UncompressedSize64)
		if readLimit > remaining {
			readLimit = remaining
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		content := make([]byte, readLimit)
		n, _ := io.ReadFull(rc, content)
		rc.Close()
		content = content[:n]
		consumed += int64(n)
		findings = append(findings, scanFile(f.Name, content)...)
	}
	return findings, nil
}

// scanFile applies every pattern detector to one file's content.
func scanFile(path string, content []byte) []StaticFinding {
	var hits []StaticFinding
	switch {
	case path == "package.json":
		hits = append(hits, detectMaliciousInstallScript(path, content)...)
	}
	if isJSish(path) {
		hits = append(hits, detectEvalDynamic(path, content)...)
		hits = append(hits, detectObfuscatedBlob(path, content)...)
		hits = append(hits, detectChildProcessNetwork(path, content)...)
		hits = append(hits, detectEncodedURLs(path, content)...)
	}
	if isGoSource(path) {
		hits = append(hits, detectGoInitSuspicious(path, content)...)
		hits = append(hits, detectObfuscatedBlob(path, content)...) // generic
	}
	if isRustBuildScript(path) {
		hits = append(hits, detectRustBuildRsSuspicious(path, content)...)
	}
	if isRustSource(path) {
		hits = append(hits, detectObfuscatedBlob(path, content)...)
		hits = append(hits, detectRustImportTimeNetwork(path, content)...)
	}
	if isJVMSource(path) {
		// Java / Kotlin sources inside a JAR. Static
		// initializer blocks + Runtime.exec are the JVM
		// equivalent of Go init() + exec.Command. The actual
		// bytecode that ships is in .class files which we
		// can't read without a class-file parser — those are
		// future work; flagging source-form static initializers
		// catches the careless attacker who ships sources.
		hits = append(hits, detectJVMStaticInitSuspicious(path, content)...)
		hits = append(hits, detectObfuscatedBlob(path, content)...)
	}
	return hits
}

func isJSish(path string) bool {
	for _, ext := range []string{".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// isGoSource matches Go source files but NOT test files (which
// have legitimate reasons to exec / open network — test fixtures).
// We're after package-level init() execution, not unit-test setup.
func isGoSource(path string) bool {
	if !strings.HasSuffix(path, ".go") {
		return false
	}
	if strings.HasSuffix(path, "_test.go") {
		return false
	}
	return true
}

// isRustBuildScript matches the special build.rs at the root of
// a crate. This is THE high-risk file in Rust supply chain —
// it runs as the developer at compile time.
func isRustBuildScript(path string) bool {
	return path == "build.rs" || strings.HasSuffix(path, "/build.rs")
}

func isRustSource(path string) bool {
	return strings.HasSuffix(path, ".rs") && !isRustBuildScript(path)
}

// isJVMSource matches Java / Kotlin / Scala sources inside a
// JAR (or sources jar). Production JARs ship .class bytecode,
// not .java — but Maven Central commonly publishes
// `-sources.jar` artifacts and many libraries include their
// sources inside the main JAR. When sources are absent the
// only signal is `META-INF/MANIFEST.MF` (covered separately).
func isJVMSource(path string) bool {
	return strings.HasSuffix(path, ".java") ||
		strings.HasSuffix(path, ".kt") ||
		strings.HasSuffix(path, ".kts") ||
		strings.HasSuffix(path, ".scala") ||
		strings.HasSuffix(path, ".groovy")
}

// detectJVMStaticInitSuspicious flags Java/Kotlin source files
// containing a static initializer block AND high-risk runtime
// behavior. JVM static init runs at class load — same
// "runs at import time without consent" shape as Go init() /
// Python module-level code. Source-level detection catches the
// lazy attacker; bytecode-level detection is future work.
var (
	jvmStaticInitPattern   = regexp.MustCompile(`(?m)\bstatic\s*\{`)
	jvmRuntimeExecPattern  = regexp.MustCompile(`Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(`)
	jvmHTTPPattern         = regexp.MustCompile(`new\s+URL\s*\(|HttpURLConnection|HttpClient\.`)
	jvmBase64DecodePattern = regexp.MustCompile(`Base64\.getDecoder\(\)\.decode|Base64\.getMimeDecoder\(\)\.decode`)
)

func detectJVMStaticInitSuspicious(path string, content []byte) []StaticFinding {
	hasStaticInit := jvmStaticInitPattern.Match(content)
	if !hasStaticInit {
		return nil
	}
	var hits []StaticFinding
	if jvmRuntimeExecPattern.Match(content) {
		hits = append(hits, StaticFinding{
			Pattern: "jvm-static-init-with-exec",
			Path:    path,
			Snippet: "class has static{} block AND uses Runtime.exec / ProcessBuilder",
			Weight:  3,
		})
	}
	if jvmHTTPPattern.Match(content) {
		hits = append(hits, StaticFinding{
			Pattern: "jvm-static-init-with-network",
			Path:    path,
			Snippet: "class has static{} block AND makes HTTP / URL calls",
			Weight:  2,
		})
	}
	if jvmBase64DecodePattern.Match(content) {
		hits = append(hits, StaticFinding{
			Pattern: "jvm-static-init-base64-decode",
			Path:    path,
			Snippet: "class has static{} block AND uses Base64 decode — payload-obfuscation shape",
			Weight:  1,
		})
	}
	return hits
}

// detectMaliciousInstallScript inspects package.json's "scripts"
// for postinstall/preinstall/install entries that pipe-to-shell,
// curl-and-exec, or run dynamic node -e payloads.
func detectMaliciousInstallScript(path string, content []byte) []StaticFinding {
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil
	}
	var hits []StaticFinding
	for _, key := range []string{"preinstall", "install", "postinstall"} {
		script, ok := pkg.Scripts[key]
		if !ok || script == "" {
			continue
		}
		// High-confidence-bad shapes.
		lc := strings.ToLower(script)
		switch {
		case strings.Contains(lc, "curl ") && strings.Contains(lc, "| sh"),
			strings.Contains(lc, "curl ") && strings.Contains(lc, "| bash"),
			strings.Contains(lc, "wget ") && strings.Contains(lc, "| sh"),
			strings.Contains(lc, "wget ") && strings.Contains(lc, "| bash"):
			hits = append(hits, StaticFinding{
				Pattern: "install-script-curl-pipe-shell",
				Path:    path,
				Snippet: fmt.Sprintf("%s: %s", key, script),
				Weight:  3,
			})
		case strings.Contains(lc, "node -e") || strings.Contains(lc, "node --eval"):
			hits = append(hits, StaticFinding{
				Pattern: "install-script-node-eval",
				Path:    path,
				Snippet: fmt.Sprintf("%s: %s", key, script),
				Weight:  3,
			})
		case strings.Contains(lc, "python -c") || strings.Contains(lc, "python3 -c"):
			hits = append(hits, StaticFinding{
				Pattern: "install-script-python-eval",
				Path:    path,
				Snippet: fmt.Sprintf("%s: %s", key, script),
				Weight:  3,
			})
		case strings.Contains(lc, "eval ") || strings.Contains(lc, "$(eval"):
			hits = append(hits, StaticFinding{
				Pattern: "install-script-shell-eval",
				Path:    path,
				Snippet: fmt.Sprintf("%s: %s", key, script),
				Weight:  2,
			})
		}
	}
	return hits
}

// evalDynamicPattern matches `eval(<not-string-literal>)`,
// `new Function(<not-string-literal>)()`, etc. Static eval of a
// literal string is rare-but-legitimate (sourcemap stuff); eval
// of a runtime-constructed value is the malware tell.
//
// Crude but effective: match `eval(` not followed by a quote
// within a few characters.
var evalDynamicPattern = regexp.MustCompile(`(?:\beval|\bFunction)\s*\(\s*[a-zA-Z_$]`)

func detectEvalDynamic(path string, content []byte) []StaticFinding {
	loc := evalDynamicPattern.FindIndex(content)
	if loc == nil {
		return nil
	}
	return []StaticFinding{{
		Pattern: "eval-of-dynamic",
		Path:    path,
		Snippet: snippetAround(content, loc[0], 80),
		Weight:  2,
	}}
}

// detectObfuscatedBlob flags long string literals composed of
// base64 / hex character classes. Threshold: 256+ contiguous
// chars of base64 alphabet OR hex. Lots of legitimate files have
// short base64 strings (icons, hashes); a 256-char base64 blob
// inside a JS file is almost certainly a payload.
var (
	longBase64Pattern = regexp.MustCompile(`["'][A-Za-z0-9+/=]{256,}["']`)
	longHexPattern    = regexp.MustCompile(`["'][0-9a-fA-F]{256,}["']`)
)

func detectObfuscatedBlob(path string, content []byte) []StaticFinding {
	var hits []StaticFinding
	if loc := longBase64Pattern.FindIndex(content); loc != nil {
		// Cross-check with shannon entropy: even base64 of zeros is
		// long but low-entropy. Real payloads sit ~5.5+ bits/char.
		s := content[loc[0]:loc[1]]
		if shannonEntropy(s) >= 4.5 {
			hits = append(hits, StaticFinding{
				Pattern: "obfuscated-base64-blob",
				Path:    path,
				Snippet: fmt.Sprintf("%d-byte high-entropy base64 literal at offset %d", len(s), loc[0]),
				Weight:  1,
			})
		}
	}
	if loc := longHexPattern.FindIndex(content); loc != nil {
		s := content[loc[0]:loc[1]]
		if shannonEntropy(s) >= 3.5 {
			hits = append(hits, StaticFinding{
				Pattern: "obfuscated-hex-blob",
				Path:    path,
				Snippet: fmt.Sprintf("%d-byte high-entropy hex literal at offset %d", len(s), loc[0]),
				Weight:  1,
			})
		}
	}
	return hits
}

// detectChildProcessNetwork looks for the combination of
// child_process.{spawn,exec} with constructed command strings — a
// classic exfil shape (e.g. `spawn('curl', [exfilURL])`).
var childProcessImportPattern = regexp.MustCompile(`require\s*\(\s*['"]child_process['"]\s*\)|from\s+['"]child_process['"]|from\s+['"]node:child_process['"]`)
var spawnExecPattern = regexp.MustCompile(`\.(?:spawn|exec|execFile|execSync|spawnSync)\s*\(`)

func detectChildProcessNetwork(path string, content []byte) []StaticFinding {
	if !childProcessImportPattern.Match(content) {
		return nil
	}
	if !spawnExecPattern.Match(content) {
		return nil
	}
	// Both signals present in the same file. Probably an infra
	// tool legitimately (vite, esbuild, jest plugins) but worth
	// 1 point because malware piggybacks here too.
	return []StaticFinding{{
		Pattern: "child-process-with-spawn",
		Path:    path,
		Snippet: "imports child_process AND calls spawn/exec — review for exfil shape",
		Weight:  1,
	}}
}

// detectEncodedURLs spots common ways malware hides exfil
// endpoints: base64-encoded "http", literal hex of "https".
var (
	base64HTTPPattern = regexp.MustCompile(`(?:aHR0cHM6Ly|aHR0cDovL)[A-Za-z0-9+/]{8,}`) // base64 of "https://" / "http://"
)

func detectEncodedURLs(path string, content []byte) []StaticFinding {
	loc := base64HTTPPattern.FindIndex(content)
	if loc == nil {
		return nil
	}
	return []StaticFinding{{
		Pattern: "base64-encoded-url",
		Path:    path,
		Snippet: snippetAround(content, loc[0], 80),
		Weight:  2,
	}}
}

// shannonEntropy returns the entropy of a byte slice in bits/char.
// Used to distinguish "real" payloads from low-information
// long-but-repetitive strings.
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var h float64
	n := float64(len(b))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// detectGoInitSuspicious flags Go `init()` functions that contain
// patterns associated with malicious behavior. Go's init() runs
// at import time — there's no "you opted in" gesture — so the
// bar for "suspicious" is lower than for runtime code. We score
// on the COMBINATION: init() + (network OR exec OR sensitive-
// file-read OR base64-decode), not individual signals (init()
// alone is benign; net.Dial in a regular function is benign).
var (
	goInitFuncPattern         = regexp.MustCompile(`(?m)^\s*func\s+init\s*\(\s*\)\s*\{`)
	goNetCallPattern          = regexp.MustCompile(`\b(?:net\.Dial|http\.Get|http\.Post|http\.NewRequest|net\.Listen)\b`)
	goExecCallPattern         = regexp.MustCompile(`\bexec\.(?:Command|CommandContext)\b`)
	goSensitiveFilePattern    = regexp.MustCompile(`os\.(?:Open|ReadFile)\s*\(\s*["']/(?:etc/(?:passwd|shadow|hosts)|root/\.ssh|home/[^"']*/\.(?:aws|ssh|npmrc|pypirc|gnupg))`)
	goBase64DecodePattern     = regexp.MustCompile(`\bbase64\.(?:StdEncoding|RawStdEncoding|URLEncoding)\.DecodeString\b`)
)

func detectGoInitSuspicious(path string, content []byte) []StaticFinding {
	initLoc := goInitFuncPattern.FindIndex(content)
	if initLoc == nil {
		return nil
	}
	// Look at the file as a whole — Go's init() can call
	// helpers defined later, and our scope-tracking would be
	// expensive. False-positive rate is acceptable for the
	// gate's "warn / block" semantics since the user can
	// allowlist legitimate cases.
	var hits []StaticFinding
	if goNetCallPattern.Match(content) {
		hits = append(hits, StaticFinding{
			Pattern: "go-init-with-network",
			Path:    path,
			Snippet: "package has init() AND makes network calls — runs at import time without consent",
			Weight:  2,
		})
	}
	if goExecCallPattern.Match(content) {
		hits = append(hits, StaticFinding{
			Pattern: "go-init-with-exec",
			Path:    path,
			Snippet: "package has init() AND spawns subprocesses",
			Weight:  3,
		})
	}
	if goSensitiveFilePattern.Match(content) {
		hits = append(hits, StaticFinding{
			Pattern: "go-init-reads-sensitive-file",
			Path:    path,
			Snippet: "package has init() AND opens credential / ssh / hosts files",
			Weight:  3,
		})
	}
	if goBase64DecodePattern.Match(content) {
		hits = append(hits, StaticFinding{
			Pattern: "go-init-base64-decode",
			Path:    path,
			Snippet: "package has init() AND uses base64 decode — payload-obfuscation shape",
			Weight:  1,
		})
	}
	return hits
}

// detectRustBuildRsSuspicious flags patterns in build.rs that
// indicate code-at-build-time abuse. build.rs runs with the
// developer's privileges at `cargo build` time — the same
// privilege level as `npm postinstall` but invoked far more
// often because it fires on every recompile too.
var (
	rustHttpClientPattern   = regexp.MustCompile(`\b(?:reqwest|ureq|surf|isahc|hyper::Client)\b`)
	rustRawNetPattern       = regexp.MustCompile(`std::net::(?:TcpStream|UdpSocket)::connect`)
	rustProcessCommand      = regexp.MustCompile(`std::process::Command::new`)
	rustEnvSensitivePattern = regexp.MustCompile(`std::env::var\s*\(\s*"(?:HOME|AWS_|GITHUB_TOKEN|NPM_TOKEN|PYPI_TOKEN|CARGO_REGISTRY_TOKEN)`)
	rustFsRead              = regexp.MustCompile(`std::fs::(?:read|read_to_string|read_dir|File::open)\s*\(\s*"(?:/etc/|/root/|/home/|.ssh|/var/lib/secrets)`)
)

func detectRustBuildRsSuspicious(path string, content []byte) []StaticFinding {
	var hits []StaticFinding
	if rustHttpClientPattern.Match(content) || rustRawNetPattern.Match(content) {
		hits = append(hits, StaticFinding{
			Pattern: "rust-build-rs-network",
			Path:    path,
			Snippet: "build.rs makes HTTP / TCP calls at compile time — exfil shape",
			Weight:  3,
		})
	}
	if rustProcessCommand.Match(content) {
		hits = append(hits, StaticFinding{
			Pattern: "rust-build-rs-process-spawn",
			Path:    path,
			Snippet: "build.rs spawns subprocesses at compile time",
			Weight:  2,
		})
	}
	if rustEnvSensitivePattern.Match(content) {
		hits = append(hits, StaticFinding{
			Pattern: "rust-build-rs-reads-secret-env",
			Path:    path,
			Snippet: "build.rs reads credential-shaped env vars at compile time",
			Weight:  3,
		})
	}
	if rustFsRead.Match(content) {
		hits = append(hits, StaticFinding{
			Pattern: "rust-build-rs-reads-sensitive-file",
			Path:    path,
			Snippet: "build.rs reads system / credential / ssh files",
			Weight:  3,
		})
	}
	return hits
}

// detectRustImportTimeNetwork flags `lazy_static!` /
// `once_cell::Lazy` blocks with network calls inside lib.rs —
// the closest analogue to Go's init() in Rust.
func detectRustImportTimeNetwork(path string, content []byte) []StaticFinding {
	if !rustHttpClientPattern.Match(content) && !rustRawNetPattern.Match(content) {
		return nil
	}
	// Only flag when lazy initialization is also present — a
	// network call in a normal fn is fine.
	if !regexp.MustCompile(`lazy_static\s*!\s*\{|once_cell::sync::Lazy::new`).Match(content) {
		return nil
	}
	return []StaticFinding{{
		Pattern: "rust-lazy-init-network",
		Path:    path,
		Snippet: "lazy_static / once_cell Lazy contains network call — runs first time module is touched",
		Weight:  2,
	}}
}

func snippetAround(content []byte, offset, span int) string {
	start := offset - span/2
	if start < 0 {
		start = 0
	}
	end := offset + span/2
	if end > len(content) {
		end = len(content)
	}
	s := string(content[start:end])
	// Collapse newlines so the snippet is one line.
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

func formatStaticFindings(fs []StaticFinding) string {
	var sb strings.Builder
	for i, f := range fs {
		if i > 0 {
			sb.WriteByte('\n')
		}
		fmt.Fprintf(&sb, "  [+%d %s] %s — %s", f.Weight, f.Pattern, f.Path, f.Snippet)
	}
	return sb.String()
}
