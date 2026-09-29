package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ResolveNuGetTree resolves what `dotnet add package <id>` would
// install (direct + transitive). Approach:
//   1. tmpdir with a minimal *.csproj declaring a PackageReference
//      for each requested package + RestorePackagesWithLockFile
//      so dotnet writes packages.lock.json.
//   2. `dotnet restore --use-lock-file --packages <tmp>/.nuget`
//      resolves and writes packages.lock.json. The .nupkg bytes
//      land in the temp dir's package cache and get cleaned up
//      with the tmpdir; nothing runs on the user's machine.
//   3. Parse packages.lock.json. Every entry carries a contentHash
//      (base64-encoded sha512 of the .nupkg) which we use as
//      PackageRef.Integrity.
//
// NuGet packages do NOT execute install scripts by default
// (init.ps1 was a packages.config-era thing; modern PackageReference
// projects don't run code on restore). So restoring into a temp dir
// is safe even before the gate decides whether to allow it.
//
// dotnetPath is the absolute path to the real `dotnet` binary so
// the gate's own shim doesn't loop.
func ResolveNuGetTree(ctx context.Context, dotnetPath string, installArgs []string) ([]PackageRef, error) {
	if len(installArgs) == 0 {
		return nil, errors.New("no NuGet packages supplied")
	}
	dotnet := dotnetPath
	if dotnet == "" {
		dotnet = "dotnet"
	}
	pkgs, err := parseDotnetAddArgs(installArgs)
	if err != nil {
		return nil, err
	}

	tmp, err := os.MkdirTemp("", "chdora-gate-nuget-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	var csproj strings.Builder
	csproj.WriteString(`<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
    <NoWarn>NU1701;NU1605</NoWarn>
  </PropertyGroup>
  <ItemGroup>
`)
	for _, p := range pkgs {
		v := p.version
		if v == "" {
			v = "*"
		}
		fmt.Fprintf(&csproj, "    <PackageReference Include=%q Version=%q />\n", p.name, v)
	}
	csproj.WriteString(`  </ItemGroup>
</Project>
`)
	if err := os.WriteFile(filepath.Join(tmp, "resolve.csproj"), []byte(csproj.String()), 0o644); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, dotnet,
		"restore",
		"--use-lock-file",
		"--packages", filepath.Join(tmp, ".nuget"),
		"--no-cache",
		"--force-evaluate",
		"--verbosity", "quiet",
	)
	cmd.Dir = tmp
	// Suppress the dotnet CLI first-run telemetry banner so its
	// stdout doesn't get mistaken for a resolver failure.
	cmd.Env = append(os.Environ(),
		"DOTNET_NOLOGO=1",
		"DOTNET_CLI_TELEMETRY_OPTOUT=1",
		"DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapPMError("dotnet", "restore --use-lock-file", out, err)
	}

	data, err := os.ReadFile(filepath.Join(tmp, "packages.lock.json"))
	if err != nil {
		return nil, fmt.Errorf("read packages.lock.json: %w", err)
	}
	return parseNuGetLockTree(data, pkgs)
}

type dotnetPkgArg struct {
	name    string
	version string
}

// parseDotnetAddArgs accepts the form
//
//	<id> [--version <v>]   or   <id>@<v>   or   <id>:<v>
//
// chdora's classifyGateArgs strips the "add" / "package" tokens
// before forwarding, but we re-strip "package" as a safety net so
// the resolver works if called with the full `add package <id>`
// args directly.
func parseDotnetAddArgs(args []string) ([]dotnetPkgArg, error) {
	if len(args) > 0 && args[0] == "package" {
		args = args[1:]
	}
	var out []dotnetPkgArg
	var nextIsVersion bool
	for _, a := range args {
		if nextIsVersion {
			if len(out) > 0 {
				out[len(out)-1].version = a
			}
			nextIsVersion = false
			continue
		}
		if a == "" {
			continue
		}
		if a == "-v" || a == "--version" {
			nextIsVersion = true
			continue
		}
		if strings.HasPrefix(a, "--version=") {
			v := strings.TrimPrefix(a, "--version=")
			if len(out) > 0 {
				out[len(out)-1].version = v
			}
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		dep := dotnetPkgArg{name: a}
		// Shorthand: pkg@1.0 or pkg:1.0.
		if i := strings.LastIndex(a, "@"); i > 0 {
			dep.name = a[:i]
			dep.version = a[i+1:]
		} else if i := strings.LastIndex(a, ":"); i > 0 {
			dep.name = a[:i]
			dep.version = a[i+1:]
		}
		out = append(out, dep)
	}
	if len(out) == 0 {
		return nil, errors.New("no resolvable NuGet packages in args")
	}
	return out, nil
}

// parseNuGetLockTree walks packages.lock.json. Schema (v1/v2):
//
//	{
//	  "version": 2,
//	  "dependencies": {
//	    "net8.0": {
//	      "Newtonsoft.Json": {
//	        "type": "Direct" | "Transitive",
//	        "resolved": "13.0.3",
//	        "contentHash": "base64-sha512"
//	      },
//	      ...
//	    }
//	  }
//	}
//
// Multiple target frameworks each get their own sub-map. We emit
// one PackageRef per unique (name, version) seen across frameworks.
func parseNuGetLockTree(data []byte, directs []dotnetPkgArg) ([]PackageRef, error) {
	var lock struct {
		Dependencies map[string]map[string]struct {
			Type        string `json:"type"`
			Resolved    string `json:"resolved"`
			ContentHash string `json:"contentHash"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse packages.lock.json: %w", err)
	}
	directNames := map[string]struct{}{}
	for _, d := range directs {
		directNames[d.name] = struct{}{}
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, tfm := range lock.Dependencies {
		for name, entry := range tfm {
			if entry.Resolved == "" {
				continue
			}
			key := name + "@" + entry.Resolved
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			_, isDirect := directNames[name]
			integrity := ""
			if entry.ContentHash != "" {
				integrity = "sha512-" + entry.ContentHash
			}
			refs = append(refs, PackageRef{
				Ecosystem: "nuget",
				Name:      name,
				Version:   entry.Resolved,
				Direct:    isDirect,
				Integrity: integrity,
			})
		}
	}
	return refs, nil
}
