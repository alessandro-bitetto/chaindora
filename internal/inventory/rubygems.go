package inventory

import (
	"bufio"
	"os"
	"strings"
)

// parseGemfileLock parses Bundler's Gemfile.lock. The format is
// column-aligned text with section headers; we only care about
// the GEM section (which contains the resolved tree) and within
// it the four-space-indented `<name> (<version>)` lines.
//
// Example:
//
//	GEM
//	  remote: https://rubygems.org/
//	  specs:
//	    actionpack (7.0.4)
//	      activesupport (= 7.0.4)
//	    activesupport (7.0.4)
//	      concurrent-ruby (~> 1.0, >= 1.0.2)
//
//	PLATFORMS
//	  ruby
//
//	DEPENDENCIES
//	  rails (~> 7.0)
//
// We deliberately ignore the DEPENDENCIES section (those are
// loose version constraints, not resolved versions) and any
// GIT/PATH sources (chaindora has no trust model for git-sourced
// gems yet — that's the v0.11 git-URL trust evaluator).
func parseGemfileLock(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var packages []Package
	inGEM := false
	inSpecs := false
	seen := map[string]struct{}{}

	scanner := bufio.NewScanner(f)
	// Default 64KB buffer is fine for Gemfile.lock — biggest seen
	// is a Rails monorepo at ~10KB.
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Section headers are at column 0.
		if len(line) > 0 && line[0] != ' ' {
			inGEM = trimmed == "GEM"
			inSpecs = false
			continue
		}
		if !inGEM {
			continue
		}
		// Enter the specs block once we see `  specs:` at 2
		// spaces. Exit when indentation drops back to 2 spaces
		// for any other key.
		if trimmed == "specs:" && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}
		// Within specs:
		//   "    actionpack (7.0.4)" → resolved gem (4-space indent)
		//   "      activesupport (= 7.0.4)" → dependency (6-space indent, version constraint)
		// We want the 4-space-indent lines only — those are the
		// resolved versions.
		if !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "      ") {
			continue
		}
		name, version, ok := parseGemSpecLine(trimmed)
		if !ok {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		packages = append(packages, Package{
			Ecosystem:  EcosystemRubyGems,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemRubyGems, name, version),
			SourcePath: path,
		})
	}
	if err := scanner.Err(); err != nil {
		return packages, err
	}
	return packages, nil
}

// parseGemSpecLine extracts (name, version) from
// "<name> (<version>)". Returns ok=false when the version is a
// constraint expression (contains "~>", ">=", etc.) — that's a
// dependency line we should be ignoring at this indent level.
func parseGemSpecLine(s string) (name, version string, ok bool) {
	open := strings.LastIndex(s, "(")
	close := strings.LastIndex(s, ")")
	if open < 0 || close < open {
		return "", "", false
	}
	name = strings.TrimSpace(s[:open])
	version = strings.TrimSpace(s[open+1 : close])
	// Bundler resolved versions are plain (e.g. "7.0.4"). Lines
	// with constraint operators are deps, not resolutions.
	if strings.ContainsAny(version, "~<>=") {
		return "", "", false
	}
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}
