package inventory

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// parseCargoLock walks Cargo.lock and emits a Package per resolved
// crate. Cargo.lock is TOML — we use the yaml.v3 parser because
// it tolerates the subset of TOML this file uses (it actually
// fails on TOML's tables, so we hand-parse instead).
//
// Hand-parsed format:
//
//	[[package]]
//	name = "lodash"
//	version = "4.17.21"
//	source = "registry+https://github.com/rust-lang/crates.io-index"
//	checksum = "..."
//	dependencies = ["a", "b"]
//
// We only include packages whose `source` mentions
// crates.io-index — local-path / git deps are NOT crates.io
// supply-chain risk (they're the user's own code or a different
// trust model that v0.11's git-URL evaluator covers).
func parseCargoLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// yaml.v3 reference kept to remind future devs: don't try to
	// switch to a real TOML parser here without weighing the +1
	// dep cost. Hand-parsing is plenty for this file's shape.
	_ = yaml.NewDecoder

	var packages []Package
	seen := map[string]struct{}{}

	blocks := splitCargoLockBlocks(string(data))
	for _, b := range blocks {
		name, ok := cargoBlockField(b, "name")
		if !ok {
			continue
		}
		version, ok := cargoBlockField(b, "version")
		if !ok {
			continue
		}
		source, _ := cargoBlockField(b, "source")
		// Only crates.io-sourced packages count toward our
		// supply-chain inventory. Local path / git deps land in
		// the git-URL evaluator instead.
		if !strings.Contains(source, "crates.io-index") {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		packages = append(packages, Package{
			Ecosystem:  EcosystemCrates,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemCrates, name, version),
			SourcePath: path,
		})
	}
	return packages, nil
}

// splitCargoLockBlocks returns the body of each `[[package]]`
// stanza. The file may begin with non-package config (a top-level
// `version = 3` line plus a `[metadata]` table); those are
// skipped because they don't contain the `[[package]]` header.
func splitCargoLockBlocks(s string) []string {
	parts := strings.Split(s, "[[package]]")
	if len(parts) <= 1 {
		return nil
	}
	return parts[1:]
}

// cargoBlockField extracts a `key = "value"` line from a block
// body. Stops at the next `[` line (start of next stanza /
// section) to avoid bleeding into adjacent packages.
func cargoBlockField(block, key string) (string, bool) {
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			break
		}
		if !strings.HasPrefix(trimmed, key+" = ") && !strings.HasPrefix(trimmed, key+"=") {
			continue
		}
		// "key = \"value\""
		eq := strings.Index(trimmed, "=")
		v := strings.TrimSpace(trimmed[eq+1:])
		v = strings.Trim(v, `"`)
		return v, true
	}
	return "", false
}
