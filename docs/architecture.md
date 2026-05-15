# Architecture

This document explains how `chaindora` is organized and where to plug new
behavior in. It complements [CONTRIBUTING.md](../CONTRIBUTING.md).

## Goals

`chaindora` is the answer to one question: *did I get hit by a supply
chain attack?* That framing drives every design choice:

- **Two surfaces, not one.** The compromise may sit inside the project
  tree (`scan`) *or* on the developer's machine (`forensics`); both must
  be cheap to check.
- **Lots of detectors, one pipeline.** OSV.dev, the incident pack, host
  forensics, and behavioral heuristics all emit the same
  `findings.Finding` shape so downstream tooling (SARIF, JSONL, GitHub
  annotations) doesn't care which detector produced what.
- **Fast and offline by default.** OSV queries hit a network; everything
  else (incidents, host scan, heuristics minus `--fresh-popular`) runs
  with no external calls. `chdora scan . --skip-osv` is a sane
  fallback when offline.

## Data flow

```
                +-------------------+
                |  filesystem tree  |
                +---------+---------+
                          |
                  inventory.Scan()
                          |
                          v
              +-----------+-----------+
              |   inventory.Inventory  |
              |  (Packages + Sources)  |
              +-----------+-----------+
                          |
   +----------+---------+ | +---------+---------+--------+
   |          |         | | |         |         |        |
   v          v         v v v         v         v        v
 osvioc   incident  hostforen.   heuristic  (P4 static AST scan, future)
   |          |         |          |
   +----------+---------+----------+
                          |
                          v
                 findings.Finding[]
                          |
        +-----------------+--------------------+
        |        |        |       |            |
        v        v        v       v            v
       text    json     jsonl   sarif      github annotations
```

The shared types live in `internal/findings`; everything emits and
consumes the same `Finding` struct.

## Module layout

```
cmd/chdora/                  -- entry point (cobra root)
internal/
  cli/                          -- top-level commands
    root.go     scan.go         forensics.go     ci.go     render.go
  inventory/                    -- lockfile / manifest / config parsers
    inventory.go                -- Scan dispatcher + Package + Source types
    npm.go      pip.go          yarn.go pnpm.go uv.go pipfile.go
    ghactions.go gitlabci.go    bitbucket.go circleci.go azure.go
    docker.go   purl.go
  osv/                          -- OSV.dev client + CVSS v3 parser
    client.go   cvss.go
  incidents/                    -- incident-pack YAML loader (types, ResolveDir)
  findings/                     -- normalized Finding shape + emitters
    finding.go  sarif.go        jsonl.go ghannotations.go
  detectors/
    osvioc/                     -- OSV-IOC detector
    incident/                   -- incident-pack matcher
    hostforensics/              -- tokens, shell rc, file-artifact hunt
    heuristic/                  -- behavioral checks (no external IOC list)
incidents/                      -- curated incident YAMLs (root of repo)
testdata/                       -- fixtures for tests + demos
```

## Finding shape

```go
type Finding struct {
    Detector   string              // e.g. "osv-ioc", "incident-pack",
                                   //      "heuristic:typosquat",
                                   //      "hostforensics:shellrc"
    PURL       string              // pkg:<type>/<name>@<version>
    Ecosystem  inventory.Ecosystem // e.g. "npm", "Docker", "GitHub Actions"
    Name       string
    Version    string
    VulnID     string              // GHSA / CVE / incident-pack ID / HEUR-*
    Summary    string              // human-readable, single sentence preferred
    Severity   Severity            // CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    References []string
    SourcePath string              // file path that triggered the finding
}
```

The `Severity` value is meaningful: SARIF maps it to `error` / `warning`
/ `note` levels, `chdora ci --fail-on critical,high` filters on it,
GitHub code-scanning sorts by the corresponding `security-severity` CVSS
proxy (9.8 / 8.0 / 5.5 / 3.0). Pick deliberately.

## Severity policy

| Severity | Use it for |
|---|---|
| **CRITICAL** | Confirmed remote-code-execution / credential-stealer in a real, currently-installed package or workflow file. Incident-pack package matches, Shai-Hulud worm artifacts. |
| **HIGH** | OSV-reported CVSS ≥ 7.0, suspicious patterns with low false-positive rates (`curl\|bash` in CI scripts, eval-of-base64), maintainer-account compromise indicators (fresh-popular). |
| **MEDIUM** | OSV-reported CVSS 4.0–6.9, npm dep install scripts (most legit libraries don't ship them), typosquat candidates, dep-confusion without `.npmrc`. |
| **LOW** | Informational findings, common configurations worth surfacing (own project's install scripts, unpinned CI refs, dep-confusion with `.npmrc` but no scope rule). |
| **UNKNOWN** | OSV record lacked a parseable CVSS vector. |

## Adding a detector

A detector is a function (or type) that:

1. Reads an `*inventory.Inventory` plus optionally the scan root.
2. Emits `[]findings.Finding` with a unique `Detector` string.

The minimum surface for a new detector package:

```go
package mydetector

func Detect(ctx context.Context, inv *inventory.Inventory, scanRoot string) ([]findings.Finding, error) {
    var out []findings.Finding
    // ... walk inv.Packages and/or scanRoot ...
    return out, nil
}
```

Wire it into `cli/scan.go` and `cli/ci.go` behind a `--skip-X` flag.
Tests use in-memory `inventory.Inventory` fixtures plus `t.TempDir()` for
filesystem cases. See `internal/detectors/heuristic/heuristic_test.go`
for an example.

## Adding an inventory parser

The dispatcher in `inventory.Scan()` is intentionally a giant switch.
Adding a parser is three edits:

1. New file `internal/inventory/<name>.go` exporting `parseXxx(path)`.
2. New case in `inventory.Scan()`'s basename switch *or* path-pattern
   check.
3. If the parser handles a CI YAML that can contain `image:` refs, also
   call `appendDockerRefs(inv, path)` after the structural parse — this
   wires the file into the Docker scanner for free.

## OSV ecosystem mapping

`internal/detectors/osvioc/osvioc.go` has an `osvEcosystem()` switch
that maps `inventory.Ecosystem` → OSV's ecosystem identifier. Only
ecosystems OSV actually catalogs (npm, PyPI, OCI) should be added there;
the rest are handled by the incident pack and heuristics.

## Testing convention

- Table-driven tests for every parser and helper.
- `httptest.Server` for anything that would hit a network in production.
- `testdata/` fixtures are deliberately tiny — just enough to exercise
  parser edge cases. Larger fixtures live in tests' `tmpDir`.
