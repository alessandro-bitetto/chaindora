package inventory

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

var pypiNormRe = regexp.MustCompile(`[-_.]+`)

// NormalizePyPIName applies PEP 503 normalization: lowercase, runs of [-_.] → "-".
func NormalizePyPIName(name string) string {
	return strings.ToLower(pypiNormRe.ReplaceAllString(name, "-"))
}

// normalizePyPIName is kept as a private alias for backward-compatibility
// within the package.
func normalizePyPIName(name string) string { return NormalizePyPIName(name) }

// parsePipRequirements handles exact pins (name==version). Range specifiers,
// editable installs, and -r includes are intentionally skipped in v1.
func parsePipRequirements(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Package
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if !strings.Contains(line, "==") {
			continue
		}
		parts := strings.SplitN(line, "==", 2)
		name := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])
		if i := strings.Index(name, "["); i >= 0 {
			name = name[:i]
		}
		if i := strings.IndexAny(version, " ;"); i >= 0 {
			version = strings.TrimSpace(version[:i])
		}
		nn := normalizePyPIName(name)
		out = append(out, Package{
			Ecosystem:  EcosystemPyPI,
			Name:       nn,
			Version:    version,
			PURL:       PURL(EcosystemPyPI, nn, version),
			SourcePath: path,
		})
	}
	return out, sc.Err()
}

// parsePoetryLock is a lightweight scanner over poetry.lock's TOML output. It
// reads sequential [[package]] blocks and pulls out the "name" and "version"
// fields. Skipping a full TOML dependency keeps the binary small.
func parsePoetryLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")

	var out []Package
	var inPkg bool
	var name, version string

	flush := func() {
		if inPkg && name != "" && version != "" {
			nn := normalizePyPIName(name)
			out = append(out, Package{
				Ecosystem:  EcosystemPyPI,
				Name:       nn,
				Version:    version,
				PURL:       PURL(EcosystemPyPI, nn, version),
				SourcePath: path,
			})
		}
		inPkg = false
		name = ""
		version = ""
	}

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		switch {
		case line == "[[package]]":
			flush()
			inPkg = true
		case strings.HasPrefix(line, "["):
			flush()
		case inPkg && strings.HasPrefix(line, "name"):
			name = extractTomlString(line)
		case inPkg && strings.HasPrefix(line, "version"):
			version = extractTomlString(line)
		}
	}
	flush()
	return out, nil
}

func extractTomlString(line string) string {
	i := strings.Index(line, "=")
	if i < 0 {
		return ""
	}
	v := strings.TrimSpace(line[i+1:])
	return strings.Trim(v, `"'`)
}
