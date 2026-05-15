package osv

import (
	"sort"
	"strconv"
	"strings"
)

// MinFixedInMajor walks vuln's Affected ranges and returns the smallest
// fixed-version that is (a) greater than `current` and (b) shares the
// same SemVer major. The point: a fix command should pin to the
// minimum-safe-version inside the current major, not blindly jump to
// `@latest` which can cross majors and break peer dependencies.
//
// ecosystem filters the Affected entries (npm records often include both
// npm and other ecosystems). Returns "" if no in-major fix exists —
// caller should fall back to a manual upgrade plan (the only way out is
// a major bump, which the user must consent to).
//
// SemVer parsing is permissive on prerelease/build suffixes (1.2.3-rc.1
// is treated as 1.2.3 with the suffix preserved for tie-breaking). When
// `current` doesn't parse as SemVer (PEP 440 etc.) we return "" because
// in-major comparisons aren't well-defined.
func MinFixedInMajor(v *Vulnerability, ecosystem, current string) string {
	if v == nil {
		return ""
	}
	cur, ok := parseSemver(current)
	if !ok {
		return ""
	}
	var candidates []semver
	for _, aff := range v.Affected {
		if !ecosystemMatches(aff.Package.Ecosystem, ecosystem) {
			continue
		}
		for _, r := range aff.Ranges {
			if r.Type != "SEMVER" {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed == "" {
					continue
				}
				fix, ok := parseSemver(e.Fixed)
				if !ok {
					continue
				}
				if fix.Major != cur.Major {
					continue
				}
				if !fix.GreaterThan(cur) {
					continue
				}
				candidates = append(candidates, fix)
			}
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].LessThan(candidates[j])
	})
	return candidates[0].String()
}

// ecosystemMatches handles OSV's case-insensitive ecosystem names and the
// occasional `ECOSYSTEM:registry` suffixes (e.g. "OCI:docker.io"). We
// compare on the prefix before any colon.
func ecosystemMatches(osvEco, want string) bool {
	if osvEco == "" || want == "" {
		return false
	}
	if i := strings.Index(osvEco, ":"); i > 0 {
		osvEco = osvEco[:i]
	}
	return strings.EqualFold(osvEco, want)
}

// semver is a minimal SemVer struct sufficient for in-major comparisons
// against OSV's fixed-version events. We don't need the full SemVer spec
// (build metadata, complex prerelease ordering) — just enough to pick
// the smallest fix.
type semver struct {
	Major, Minor, Patch int
	Pre                 string
}

// parseSemver accepts strings like "1.2.3", "v1.2.3", "1.2.3-rc.1",
// "1.2", "1". Returns ok=false on unparseable input. Strict-ish: tolerates
// leading "v" and missing minor/patch but rejects non-numeric segments.
func parseSemver(s string) (semver, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return semver{}, false
	}
	s = strings.TrimPrefix(s, "v")
	// Split off prerelease / build suffix.
	pre := ""
	for i, c := range s {
		if c == '-' || c == '+' {
			pre = s[i:]
			s = s[:i]
			break
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return semver{}, false
	}
	out := semver{Pre: pre}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return semver{}, false
		}
		switch i {
		case 0:
			out.Major = n
		case 1:
			out.Minor = n
		case 2:
			out.Patch = n
		}
	}
	return out, true
}

func (a semver) String() string {
	return strconv.Itoa(a.Major) + "." + strconv.Itoa(a.Minor) + "." + strconv.Itoa(a.Patch) + a.Pre
}

func (a semver) GreaterThan(b semver) bool {
	return b.LessThan(a)
}

func (a semver) LessThan(b semver) bool {
	switch {
	case a.Major != b.Major:
		return a.Major < b.Major
	case a.Minor != b.Minor:
		return a.Minor < b.Minor
	case a.Patch != b.Patch:
		return a.Patch < b.Patch
	}
	// Same numeric version. A non-empty prerelease tag means "less than"
	// the release (1.0.0-rc.1 < 1.0.0). String ordering of prereleases
	// is a rough approximation of SemVer's actual rules — good enough
	// for fix-picking, where we just want a stable tie-breaker.
	if a.Pre == "" && b.Pre != "" {
		return false
	}
	if a.Pre != "" && b.Pre == "" {
		return true
	}
	return a.Pre < b.Pre
}
