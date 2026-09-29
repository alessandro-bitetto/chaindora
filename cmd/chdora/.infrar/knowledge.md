---
schema_version: 2
id: 9a4d554a-d80e-4fbd-bba0-2bbace118466
name: chdora
node: cmd/chdora
category: app
---

## Purpose

Chaindora 0.0.1 is a Go CLI for supply-chain prevention and detection across
npm, PyPI, NuGet, Go modules and crates.io, including 15 manager commands.
Shared CI/container references and host forensics remain supported.

## Build

From the repository root, run `go build -o chdora ./cmd/chdora`,
`go test ./... -race -count=1` and `go vet ./...`. The release workflow embeds
the release version and builds macOS, Linux and Windows archives.

## Behavior and boundaries

Scan/CI commands combine inventory, OSV, incidents, source heuristics and
predictive checks. Gate commands resolve selected install forms, run current
checks and apply strict policy before handing off. Integrity history is not
a reusable approval. Archive inspection is bounded; incomplete evidence is
Unknown. Resolution is not sandboxed and the actual install is not yet bound
to the exact inspected artifacts. Several install/restore forms pass through.

Host forensics, reviewable fix plans, and optional fleet reporting use shared
finding types. Protect agent credentials and reports; deploy the HTTP fleet
server behind TLS with enrollment protection configured. There is no telemetry.

Read the repository README, docs/architecture.md, docs/threat-model.md and
docs/security-hardening.md for authoritative coverage and implementation notes.
