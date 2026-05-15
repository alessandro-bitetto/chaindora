package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the chaindora.yml per-project gate configuration.
// Discovered by walking up the directory tree from cwd until a
// `chaindora.yml` (or `.chaindora.yml`) is found, or the
// filesystem root is reached.
//
// Everything in the schema is optional — empty config = strict
// defaults, network checks against the public registries, no
// per-package overrides.
type Config struct {
	// CooldownHours overrides the gate's default 72h threshold.
	// Use values like 24 to be more permissive, 168 for a stricter
	// week-long embargo on fresh publishes.
	CooldownHours int `yaml:"cooldown_hours"`

	// AllowOnWarn flips the policy from Strict to Lenient: Warn
	// verdicts pass through. Default false (Strict).
	AllowOnWarn bool `yaml:"allow_on_warn"`

	// AllowOnUnknown lets installs proceed when the gate can't
	// reach the registry. Default false (fail-closed). Air-gapped
	// CI runs should set this true with `--allow-offline`.
	AllowOnUnknown bool `yaml:"allow_on_unknown"`

	// Allow is the per-(ecosystem, name) allowlist. Listed entries
	// skip every gate check entirely. Pin versions with
	// `<name>@<version>` to bypass for one specific release;
	// `<name>` alone bypasses every version (use sparingly).
	//
	// Example:
	//   allow:
	//     npm:
	//       - "lodash@4.17.21"        # one trusted version
	//       - "@my-org/utils"         # any version, we trust the scope
	//     pypi:
	//       - "requests"
	Allow map[string][]string `yaml:"allow"`

	// Deny is the inverse: per-(ecosystem, name) entries that are
	// always blocked, even if no other check would fire. Use for
	// "packages our team has decided not to use" (e.g. moment.js
	// in a project that standardized on date-fns).
	Deny map[string][]string `yaml:"deny"`

	// GitHosts is the per-project allowlist of git hosting
	// platforms beyond the well-known set (github.com, gitlab.com,
	// bitbucket.org, codeberg.org, sr.ht). Use for corporate
	// self-hosted Gitea / GitLab / Stash instances. Wired into
	// the git-url checker (v0.11.1).
	GitHosts []string `yaml:"git_hosts"`

	// AllowBranchRefs flips the "branch ref → Block" rule in the
	// git-url checker to Warn. Default false (strict). Set true
	// in monorepos with internal git deps that legitimately use
	// branch refs.
	AllowBranchRefs bool `yaml:"allow_branch_refs"`
}

// LoadConfig walks up from startDir looking for chaindora.yml or
// .chaindora.yml. Returns the first match. Returns nil config with
// nil error when no file is found — that's the common "running in a
// random directory" case and should not error.
func LoadConfig(startDir string) (*Config, error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", startDir, err)
	}
	for {
		for _, name := range []string{"chaindora.yml", ".chaindora.yml", "chaindora.yaml"} {
			candidate := filepath.Join(dir, name)
			info, err := os.Stat(candidate)
			if err == nil && !info.IsDir() {
				return readConfig(candidate)
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("stat %s: %w", candidate, err)
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, nil // hit filesystem root, no config found
		}
		dir = parent
	}
}

func readConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// CooldownThreshold returns the configured cooldown, or the supplied
// default when unset. Negative values are treated as default; we
// don't permit "no cooldown" via config because that's the kind of
// silent footgun this gate exists to prevent.
func (c *Config) CooldownThreshold(def time.Duration) time.Duration {
	if c == nil || c.CooldownHours <= 0 {
		return def
	}
	return time.Duration(c.CooldownHours) * time.Hour
}

// Policy returns the gate Policy implied by this config.
func (c *Config) Policy() Policy {
	if c == nil {
		return Strict()
	}
	return Policy{AllowOnWarn: c.AllowOnWarn, AllowOnUnknown: c.AllowOnUnknown}
}

// IsAllowed reports whether ref is on the allowlist. Match logic:
//   - "<name>" (no @) matches any version of name
//   - "<name>@<version>" matches that exact version
//
// Scope prefixes (`@my-org/pkg`) are supported — the leading `@`
// belongs to the package name; only an `@` AFTER the name separates
// name from version.
func (c *Config) IsAllowed(ref PackageRef) bool {
	if c == nil {
		return false
	}
	for _, entry := range c.Allow[ref.Ecosystem] {
		if matchesEntry(entry, ref.Name, ref.Version) {
			return true
		}
	}
	return false
}

// IsDenied reports whether ref is on the denylist. Same match logic
// as IsAllowed.
func (c *Config) IsDenied(ref PackageRef) bool {
	if c == nil {
		return false
	}
	for _, entry := range c.Deny[ref.Ecosystem] {
		if matchesEntry(entry, ref.Name, ref.Version) {
			return true
		}
	}
	return false
}

func matchesEntry(entry, name, version string) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return false
	}
	// Find the @ that separates name from version. For scoped
	// packages, the first @ is part of the name; the version @
	// (if any) is the next one.
	atIdx := -1
	if strings.HasPrefix(entry, "@") {
		// Skip the leading scope @; find the NEXT @.
		if i := strings.Index(entry[1:], "@"); i >= 0 {
			atIdx = i + 1
		}
	} else {
		atIdx = strings.Index(entry, "@")
	}
	if atIdx < 0 {
		return entry == name
	}
	return entry[:atIdx] == name && entry[atIdx+1:] == version
}

// AllowlistChecker is a synthetic Checker that returns Verdict=Approve
// for allowlisted packages and Verdict=Block for denylisted ones.
// Run this checker FIRST so the allowlist short-circuits the rest
// (saves a tarball download, an OSV query, etc. for trusted entries).
//
// We model this as a regular Checker so the orchestrator doesn't
// need a special "skip" path. The orchestrator can detect a
// VerdictBlock here and stop calling subsequent checkers for the
// same package — see Run's evolution toward that in v0.9.1.
type AllowlistChecker struct {
	Config *Config
}

func (a *AllowlistChecker) Name() string { return "allowlist" }

func (a *AllowlistChecker) Check(_ context.Context, ref PackageRef) CheckResult {
	r := CheckResult{Checker: a.Name()}
	if a.Config == nil {
		r.Verdict = VerdictApprove
		r.Reason = "no chaindora.yml found — allowlist inert"
		return r
	}
	if a.Config.IsDenied(ref) {
		r.Verdict = VerdictBlock
		r.Reason = "explicitly denied in chaindora.yml"
		return r
	}
	if a.Config.IsAllowed(ref) {
		r.Verdict = VerdictApprove
		r.Reason = "explicitly allowed in chaindora.yml"
		return r
	}
	r.Verdict = VerdictApprove
	r.Reason = "no allowlist match (other checkers still run)"
	return r
}
