# CLAUDE.md — Chaindora

Chaindora is the project; `chdora` is the Go CLI. Read [README.md](README.md),
[architecture](docs/architecture.md), [threat model](docs/threat-model.md) and
[hardening assessment](docs/security-hardening.md) before changing security behavior.

## Maintained scope

Only npm, PyPI, .NET/NuGet, Go modules and Rust/crates.io are dependency
ecosystems. Retain npm/yarn/pnpm/bun/deno, pip/pip3/poetry/uv/pipenv/pdm,
dotnet/paket, go and cargo. Shared CI/container-reference and host forensics
remain. Prioritize depth in this scope over adding new registry integrations.
See the README for precise parser/command coverage and limitations.

## Build and validate

```sh
go test ./... -race
go vet ./...
go build ./cmd/chdora
GOOS=linux GOARCH=amd64 go build -o /tmp/chdora-linux ./cmd/chdora
GOOS=windows GOARCH=amd64 go build -o /tmp/chdora-windows.exe ./cmd/chdora
cd website
npm ci
npm run build
```

Cross-compilation is not runtime validation. Never execute malicious fixture
payloads; tests use inert files and local HTTP servers. Keep JSON stdout clean;
progress and diagnostics belong on stderr. The static website output is
`website/dist/browser`. Releases are described in
[maintainer handoff](docs/maintainer-handoff.md); do not publish implicitly.

## Conventions

- **Go 1.22+.** Two external deps (`spf13/cobra`, `gopkg.in/yaml.v3`); add
  new ones reluctantly. `golang.org/x/term` was considered for TTY
  detection and rejected — stdlib `os.Stdin.Stat() & os.ModeCharDevice`
  works fine.
- `gofmt -s`, `go vet`, `golangci-lint` clean on every change.
- `go test ./... -race` must pass on all three OS matrix entries.
- Table-driven tests for every parser and helper. `httptest.Server` for
  anything that would hit a network in production (no live OSV in
  `go test`). Inject probes via interfaces, not concrete types.
- Path matching uses `filepath.ToSlash` + `path.Match` — **never**
  `filepath.Match` directly. On Windows the separator is `\`, so
  `filepath.Match` lets `*` cross `/`; we had a real regression caught
  by Windows CI.
- Cross-platform home dir: `os.UserHomeDir()` reads `$HOME` on Unix
  but `$USERPROFILE` on Windows. Tests that override home must
  `t.Setenv` BOTH or the Windows job will fail.
- Commit messages: subject under 70 chars; body explains **why**.
  Multi-paragraph commit bodies are fine — the commit log is the
  design history for this one-author OSS project.
- Only commit when explicitly asked. Never `git push --force` to `main`.

---

## Gate invariants

- Internal/network/parser failures return Unknown, never successful inspection.
  Warning and Unknown policy overrides are independent. Block always wins.
- Empty resolved trees refuse installation even with relaxed policy. Dry-run
  prevents final handoff on passthrough and flags-only routes as well.
- CI inventory errors remain visible in JSON/SARIF and force exit 2 independent
  of suppressions, baselines and severity policy; incomplete runs cannot update
  baselines or apply fixes.
- Preserve `*gate.PMError` output and exit codes for package-manager failures.
  Use `wrapPMError` in resolvers; CLI internal errors remain distinct.
- `CachedRun` checks republish history and always runs the current stack.
  Only nonempty Approve results with integrity are stored. Historical approvals
  never bypass current policy, intelligence or requested checks. History survives
  approval TTL; unique temporary files protect concurrent writes.
- Same package/version with changed integrity blocks pending review. Missing
  integrity disables that comparison. Different platform artifacts can also
  produce different integrity strings; do not overstate proof of compromise.
- Preserve the PATH-directory and content-marker recursion guards.
  `gate exec` parses its flags only before the manager name.
- `pmClassifiers` and `shimManagers` must agree. Retired managers are refused
  before binary lookup. Migration deletes only regular managed shim files,
  preserving custom files and symlinks.
- Command coverage is incomplete. Bare restores, npm ci and several alternative
  manager forms pass through; do not describe them as previously vetted.
  npm/yarn/pnpm/cargo have update-all resolvers; Deno/Paket inspect project state.
- Static scores deduplicate pattern names. Downloads, decompression, files,
  entries and nesting are bounded; incomplete inspection is Unknown. These
  heuristics are not a sandbox, AST analysis or complete language coverage.
- Predictive npm/PyPI credential checks run independently of version-diff.
  Their failed inspections emit configuration findings. Other predictive Unknown
  results are often suppressed; do not equate no findings with full coverage.

## Inventory and detector conventions

Keep ecosystem labels, PURL types, gate keys and OSV mappings consistent.
Populate package integrity where the format carries it. Manifest fallbacks
must yield to resolved lockfiles. Directory exclusions are shared between
inventory, project discovery and incident scanning; normalize paths on Windows.
New alternative-manager formats need fixture coverage and honest documentation.
Registry tests must use injected interfaces/local HTTP fixtures, not live services.

### `internal/findings`

- `Fingerprint` is **exported** because `osvioc/fix.go` and
  `incident/fix.go` use it for plan IDs. Don't rename without updating
  both consumers.
- The fix runner dedupes plans by `Command` (command-level) AND by
  `(ProjectDir, PackageName)` picking max `RequiredVersion`
  (package-level). Per-finding-unique data therefore belongs
  in `ManualSteps` (not deduped), not in `Description` (highest-severity
  wins).
- `RunFixes` writes diagnostic output and command stdout to
  `opts.Output` — defaults to `os.Stderr`, never `os.Stdout`. Don't
  pollute pipe-to-jq workflows.

### `internal/fixplan`

- `DiskStore.Save` writes atomically via temp-file-plus-rename. On
  `sudo` invocations it chowns the result back to `$SUDO_USER` so
  non-sudo `chdora plans list` can read what sudo just wrote.
- Plan IDs validate against path traversal — never trust the user's
  CLI arg without `validateID`.

## Don't

- Don't auto-apply credential rotation, shell rc edits, or ssh-key
  removals — those are **deliberately** `Manual` category in the fix
  runner. Adding execution there silently breaks the safety story.
- Don't add a new ecosystem without updating `osvEcosystem()`, `purl.go`,
  AND `inventory.go`'s dispatcher.
- Don't merge an incident-pack entry without at least one authoritative
  source URL in `references:`. See [docs/incident-pack.md](./docs/incident-pack.md)
  for the quality bar.
- Don't commit the `/chdora` binary (it's in `.gitignore`).
- Don't `git push --force` to `main`. Tags are immutable in published
  releases.
- Don't skip git hooks (`--no-verify`) on commits.
- Don't make gate checkers fail-open on error. Network failures return
  `Verdict=Unknown`; the policy layer decides what to do with that.

---

## Pointers

- **Threat model** — scope, attack-surface map, roadmap-prioritization
  framework: [docs/threat-model.md](./docs/threat-model.md). Start here
  when proposing a new feature: check the scope boundary and the documented security priorities.
- Architecture overview: [docs/architecture.md](./docs/architecture.md)
- Incident-pack contributor guide:
  [docs/incident-pack.md](./docs/incident-pack.md)
- CI integration recipes (GitHub Actions, GitLab, CircleCI, Bitbucket,
  Azure, Jenkins, Drone): [docs/ci-integration.md](./docs/ci-integration.md)
- Per-incident schema: [incidents/SCHEMA.md](./incidents/SCHEMA.md)
- Vulnerability disclosure: [SECURITY.md](./SECURITY.md)
