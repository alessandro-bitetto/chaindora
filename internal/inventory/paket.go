package inventory

import (
	"fmt"
	"os"
	"strings"
)

func parsePaketLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	packages, err := ParsePaketLockData(data)
	for i := range packages {
		packages[i].SourcePath = path
	}
	return packages, err
}

// ParsePaketLockData reads resolved NuGet package records. Paket indents records
// four spaces and their dependency constraints six spaces; constraints must not
// be mistaken for additional resolved versions. Shared by inventory and gate.
func ParsePaketLockData(data []byte) ([]Package, error) {
	seen := map[string]bool{}
	var out []Package
	inNuGet, foundNuGet := false, false
	for lineNumber, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if line == trimmed {
			inNuGet = line == "NUGET"
			foundNuGet = foundNuGet || inNuGet
			continue
		}
		if !inNuGet {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent != 4 {
			continue
		}
		open := strings.Index(trimmed, " (")
		close := strings.Index(trimmed, ")")
		if open <= 0 || close <= open+2 {
			return nil, fmt.Errorf("invalid Paket package record at line %d", lineNumber+1)
		}
		name, version := trimmed[:open], trimmed[open+2:close]
		if strings.ContainsAny(name, " \t") || strings.ContainsAny(version, "<>=*~^, \t") {
			return nil, fmt.Errorf("invalid Paket resolved identity at line %d", lineNumber+1)
		}
		key := strings.ToLower(name) + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Package{Ecosystem: EcosystemNuGet, Name: name, Version: version, PURL: PURL(EcosystemNuGet, name, version)})
	}
	if !foundNuGet {
		return nil, fmt.Errorf("paket.lock contains no NuGet section")
	}
	return out, nil
}
