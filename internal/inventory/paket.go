package inventory

import (
	"os"
	"strings"
)

// parsePaketLock parses Paket's bespoke paket.lock format. NUGET
// section lines look like:
//
//	NUGET
//	  remote: https://api.nuget.org/v3/index.json
//	    FSharp.Core (4.7.2)
//	    Newtonsoft.Json (13.0.3) - restriction: ...
//
// paket.lock has no content hashes; Integrity stays empty.
func parsePaketLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Package
	inNuGet := false
	for _, line := range strings.Split(string(data), "\n") {
		if line == "NUGET" {
			inNuGet = true
			continue
		}
		if line == "GITHUB" || line == "GIT" || line == "HTTP" {
			inNuGet = false
			continue
		}
		if !inNuGet {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "remote:") || trimmed == "specs:" || trimmed == "" {
			continue
		}
		open := strings.Index(trimmed, " (")
		closeIdx := strings.Index(trimmed, ")")
		if open <= 0 || closeIdx <= open {
			continue
		}
		name := trimmed[:open]
		version := trimmed[open+2 : closeIdx]
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemNuGet,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemNuGet, name, version),
			SourcePath: path,
		})
	}
	return out, nil
}
