package inventory

import (
	"os"
	"strings"
)

// parsePodfileLock parses CocoaPods' Podfile.lock. Two relevant
// sections: PODS (resolved tree) and SPEC CHECKSUMS (per-pod
// sha1). We pair them on emit.
func parsePodfileLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	type pod struct{ name, version string }
	var pods []pod
	checksums := map[string]string{}
	state := ""
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if len(line) > 0 && line[0] != ' ' && line[0] != '-' {
			switch {
			case strings.HasPrefix(trimmed, "PODS:"):
				state = "pods"
			case strings.HasPrefix(trimmed, "SPEC CHECKSUMS:"):
				state = "checksums"
			default:
				state = ""
			}
			continue
		}
		switch state {
		case "pods":
			if !strings.HasPrefix(trimmed, "- ") {
				continue
			}
			entry := strings.TrimSuffix(strings.TrimPrefix(trimmed, "- "), ":")
			open := strings.LastIndex(entry, " (")
			closeIdx := strings.LastIndex(entry, ")")
			if open < 0 || closeIdx <= open {
				continue
			}
			name := strings.TrimSpace(entry[:open])
			version := strings.TrimSpace(entry[open+2 : closeIdx])
			if strings.Contains(name, "/") {
				// Sub-pod ref — parent has its own checksum.
				continue
			}
			pods = append(pods, pod{name, version})
		case "checksums":
			if i := strings.Index(trimmed, ":"); i > 0 {
				n := strings.TrimSpace(trimmed[:i])
				h := strings.Trim(strings.TrimSpace(trimmed[i+1:]), `"`)
				checksums[n] = h
			}
		}
	}
	seen := map[string]struct{}{}
	var out []Package
	for _, p := range pods {
		key := p.name + "@" + p.version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if h := checksums[p.name]; h != "" {
			integrity = "sha1:" + h
		}
		out = append(out, Package{
			Ecosystem:  EcosystemCocoaPods,
			Name:       p.name,
			Version:    p.version,
			PURL:       PURL(EcosystemCocoaPods, p.name, p.version),
			SourcePath: path,
			Integrity:  integrity,
		})
	}
	return out, nil
}
