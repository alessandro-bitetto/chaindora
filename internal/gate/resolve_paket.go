package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolvePaketTree parses paket.lock (the .NET/F# Paket lockfile).
// Format is bespoke text:
//
//	NUGET
//	  remote: https://api.nuget.org/v3/index.json
//	    FSharp.Core (4.7.2)
//	    Newtonsoft.Json (13.0.3)
//
// Paket doesn't carry per-package hashes in paket.lock; integrity
// would require a NuGet registry fetch (similar to bundler).
// Routes to NuGet ecosystem so the OSV checker reuses the existing
// NuGet vuln database.
//
// paketPath unused (parser is cwd-only).
func ResolvePaketTree(ctx context.Context, paketPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("paket resolver requires the user's project cwd")
	}
	data, err := os.ReadFile(filepath.Join(cwd, "paket.lock"))
	if err != nil {
		return nil, fmt.Errorf("read paket.lock: %w", err)
	}
	return parsePaketLock(data), nil
}

func parsePaketLock(data []byte) []PackageRef {
	seen := map[string]struct{}{}
	var refs []PackageRef
	inNuGet := false
	for _, line := range strings.Split(string(data), "\n") {
		// Section headers are at column 0.
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
		// Skip metadata lines (`remote: ...`, `specs:`).
		if strings.HasPrefix(trimmed, "remote:") || trimmed == "specs:" || trimmed == "" {
			continue
		}
		// Package line: "Name (1.2.3)" with optional " - restriction" trailing.
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
		refs = append(refs, PackageRef{
			Ecosystem: "nuget",
			Name:      name,
			Version:   version,
		})
	}
	return refs
}
