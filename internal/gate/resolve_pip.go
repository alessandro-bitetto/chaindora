package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ResolvePipTree runs `pip install --dry-run --report <file>` to
// get the resolved install set without writing anything to
// site-packages. Output is pip's documented "installation
// report" JSON (PEP 658-adjacent — `pip --report` since 23.1):
//
//	{ "install": [ { "metadata": { "name": "x", "version": "1.2.3" } } ] }
//
// pipPath is the absolute path to the real pip binary so the
// gate's own shim can't loop into itself. Tests can pass "".
//
// We deliberately don't try to `--package-lock-only` style here
// — pip doesn't have a write-the-lock-don't-install mode like
// npm. The `--report` flow is the canonical replacement.
func ResolvePipTree(ctx context.Context, pipPath string, installArgs []string) ([]PackageRef, error) {
	if len(installArgs) == 0 {
		return nil, errors.New("no pip install args supplied")
	}
	pip := pipPath
	if pip == "" {
		pip = "pip"
	}
	// pip --report writes JSON to the supplied path. Use a temp
	// file because using "-" (stdout) intermixes pip's own log
	// chatter on some versions.
	tmpFile, err := ioutil.TempFile("", "chdora-pip-report-*.json")
	if err != nil {
		return nil, fmt.Errorf("create report tmp: %w", err)
	}
	reportPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(reportPath)

	cleaned := stripPipDryRunFlags(installArgs)
	args := append([]string{
		"install",
		"--dry-run",
		"--quiet",
		"--ignore-installed",
		"--report", reportPath,
	}, cleaned...)
	cmd := exec.CommandContext(ctx, pip, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 400 {
			snippet = snippet[:400] + "..."
		}
		return nil, fmt.Errorf("pip install --dry-run --report failed: %w\n%s", err, snippet)
	}
	return parsePipReport(reportPath, installArgs)
}

func parsePipReport(reportPath string, installArgs []string) ([]PackageRef, error) {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("read pip report: %w", err)
	}
	var report struct {
		Install []struct {
			Metadata struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"metadata"`
			IsDirect bool `json:"is_direct"`
		} `json:"install"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse pip report: %w", err)
	}
	directs := pipDirectNames(installArgs)
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, entry := range report.Install {
		name := normalizePyPIName(entry.Metadata.Name)
		version := entry.Metadata.Version
		if name == "" || version == "" {
			continue
		}
		ident := name + "@" + version
		if _, dup := seen[ident]; dup {
			continue
		}
		seen[ident] = struct{}{}
		refs = append(refs, PackageRef{
			Ecosystem: "pypi",
			Name:      name,
			Version:   version,
			Direct:    entry.IsDirect || directs[name],
		})
	}
	return refs, nil
}

// pipDirectNames extracts package names from pip install args.
// Accepts "name", "name==1.2", "name>=1.0", etc. Flags
// (anything starting with "-") and option-value pairs are
// skipped.
func pipDirectNames(args []string) map[string]bool {
	out := map[string]bool{}
	skipNext := false
	for _, a := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			// Common option-value pairs that consume the next
			// arg.
			switch a {
			case "-r", "--requirement", "-c", "--constraint",
				"--index-url", "--extra-index-url", "-i",
				"--target", "-t":
				skipNext = true
			}
			continue
		}
		// Strip extras and version constraints.
		name := a
		if i := strings.IndexAny(name, "[<>=~!@ "); i >= 0 {
			name = name[:i]
		}
		name = normalizePyPIName(name)
		if name != "" {
			out[name] = true
		}
	}
	return out
}

// normalizePyPIName canonicalizes a PyPI distribution name per
// PEP 503: lowercase + runs-of-[-_.] → single hyphen.
func normalizePyPIName(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	var b strings.Builder
	lastWasSep := false
	for _, r := range s {
		switch r {
		case '-', '_', '.':
			if !lastWasSep {
				b.WriteByte('-')
				lastWasSep = true
			}
		default:
			b.WriteRune(r)
			lastWasSep = false
		}
	}
	return strings.Trim(b.String(), "-")
}

// stripPipDryRunFlags removes flags that would interfere with our
// dry-run report path. The user might pass --dry-run too; we
// dedup. --no-deps would skip transitives which defeats the
// gate's recursive-tree intent.
func stripPipDryRunFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		switch a {
		case "--dry-run", "--report", "--no-deps":
			continue
		}
		// Drop a --report=<path> form too.
		if strings.HasPrefix(a, "--report=") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// pipReportPath is a helper for tests that want a non-tempfile
// location; not used in production paths.
func pipReportPath(dir string) string {
	return filepath.Join(dir, "pip-report.json")
}
