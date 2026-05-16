package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveCarthageTree parses Cartfile.resolved — Carthage's
// pinned dependency file. Format:
//
//	github "Alamofire/Alamofire" "5.6.4"
//	github "ReactiveX/RxSwift" "6.5.0"
//	git "https://example.com/foo.git" "abc123def..."
//
// Carthage doesn't ship per-package content hashes — only git
// tags / SHAs. The git SHA acts as integrity since force-pushing
// over a tag would change the SHA.
//
// carthagePath unused (parser is cwd-only).
func ResolveCarthageTree(ctx context.Context, carthagePath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("carthage resolver requires the user's project cwd")
	}
	data, err := os.ReadFile(filepath.Join(cwd, "Cartfile.resolved"))
	if err != nil {
		return nil, fmt.Errorf("read Cartfile.resolved: %w", err)
	}
	return parseCartfileResolved(data), nil
}

func parseCartfileResolved(data []byte) []PackageRef {
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Tokens: source "owner/repo-or-url" "version".
		fields := splitQuotedFields(trimmed)
		if len(fields) < 3 {
			continue
		}
		source, spec, version := fields[0], fields[1], fields[2]
		if source != "github" && source != "git" && source != "binary" {
			continue
		}
		key := spec + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		// Heuristic: a 40-hex-char version IS a git SHA — treat
		// as integrity.
		if len(version) == 40 && isHex(strings.ToLower(version)) {
			integrity = "git:" + strings.ToLower(version)
		}
		refs = append(refs, PackageRef{
			Ecosystem: "carthage",
			Name:      spec,
			Version:   version,
			Direct:    true,
			Integrity: integrity,
		})
	}
	return refs
}

// splitQuotedFields splits a line into tokens, treating quoted
// strings as single tokens. Whitespace separates outside of quotes.
func splitQuotedFields(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, c := range s {
		switch {
		case c == '"':
			inQuote = !inQuote
		case (c == ' ' || c == '\t') && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
