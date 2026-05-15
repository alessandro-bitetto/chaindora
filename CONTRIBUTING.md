# Contributing to chaindora

Thanks for considering a contribution. This document covers the most common
ways to help: incident-pack entries, bug reports, feature work, and
docs/tests.

## Where to start

**As of v0.7.0, the curated incident pack has a narrower scope.** The bulk
of malicious-package detection now flows through the [OpenSSF Malicious
Packages database](https://github.com/ossf/malicious-packages), federated
via OSV.dev — chdora picks up MAL-* records automatically. The curated
pack is for what OSV-formatted records *can't* express:

1. **File-artifact globs.** Worm-deployed files like
   `shai-hulud-workflow.yml` that aren't packages — OSV.dev is
   package-centric and has no way to flag a file on disk.
2. **Cross-ecosystem coverage where OSV is thin.** Browser/IDE
   extensions, Homebrew formulae, Debian system packages.
3. **Sabotage / downgrade-as-fix cases.** When the "safe version" is
   the *previous* release (Marak colors-sabotage 2022, faker 6.6.6) —
   OSV's `fixed:` field doesn't model "go back, not forward."
4. **Rich post-compromise narrative.** Editorially-curated checklists
   ("rotate npm tokens for accounts that ran `npm install` between
   14:00–17:00 UTC on 2025-09-08") that the auto-generated MAL-*
   summaries can't match.

**Don't open PRs for package-version-only incidents** — those go to
[ossf/malicious-packages](https://github.com/ossf/malicious-packages)
and reach chdora users automatically via OSV.

For everything else, the high-impact areas are:

- **Bug reports** with a minimal reproducible test case.
- **Heuristics**: new detection patterns for `internal/detectors/heuristic/`.
- **Ecosystem support**: new lockfile or CI parsers in `internal/inventory/`.
- **Documentation**: every confusing flag, undocumented edge case.

For everything else, the high-impact areas are:

- **Bug reports** with a minimal reproducible test case (a small lockfile
  fragment + expected vs actual output is ideal).
- **Heuristics**: new detection patterns for `internal/detectors/heuristic/`.
- **Ecosystem support**: new lockfile or CI parsers in `internal/inventory/`.
- **Documentation**: every confusing flag, undocumented edge case, or
  missing CI integration recipe.

## Development setup

```sh
git clone https://github.com/alessandro-bitetto/chaindora
cd chaindora
go build -o chdora ./cmd/chdora
go test ./...
```

Go 1.22+ is required. The codebase has two external dependencies:
[`spf13/cobra`](https://github.com/spf13/cobra) and
[`gopkg.in/yaml.v3`](https://gopkg.in/yaml.v3). Avoid adding more unless
necessary.

## Code style

- `gofmt -s` is the law. Run `gofmt -s -w .` before committing.
- `go vet ./...` must be clean.
- Aim for `golangci-lint run` clean too (config will land soon).
- **Comments**: explain *why*, not *what*. The code already says what.
- **No emojis** in code or documentation unless the user-facing context
  clearly calls for one (e.g. CLI prompts).

## Testing

- Every parser, detector, and emitter gets a unit test with table-driven
  cases.
- Network-dependent code uses `httptest.Server`-mocked endpoints; we
  don't hit live registries during `go test`.
- For new lockfile parsers, include a real-world fragment in the test
  fixture (with the source URL in a comment).

```sh
go test ./...
go test -run TestParseNPM ./internal/inventory   # focused
go test -cover ./...                              # with coverage
```

## Pull request flow

1. **One change per PR.** Mixing a parser refactor with a new incident is
   harder to review and harder to revert.
2. **Tests first.** Especially for parsers (lockfile/YAML edge cases) and
   detectors (regex false positives).
3. **Commit messages** follow the existing style: subject line under 70
   characters, body explaining *why*, references to source advisories or
   tickets where relevant.
4. **Run the suite locally**: `go test ./...` is the bar. The CI
   workflow in `.github/workflows/test.yml` runs the same on every push.

## Sub-areas

### Adding a CI/CD parser

1. New file in `internal/inventory/`, one parser per platform.
2. New `EcosystemX` constant in `inventory.go`.
3. New PURL type case in `internal/inventory/purl.go`.
4. Dispatcher case in `inventory.Scan()`.
5. Tests with a representative config-file fragment.
6. Wire into the Docker image-refs walker if the platform supports
   `image:` (see how P3b's `appendDockerRefs` works).

### Adding a heuristic

1. New file in `internal/detectors/heuristic/`.
2. Export a `detect<Name>(inv, scanRoot)` function returning
   `[]findings.Finding`.
3. Call from `heuristic.Detector.Detect`.
4. Pick severity carefully (see "severity policy" in
   [docs/architecture.md](./docs/architecture.md)).
5. Tests covering both positive and negative cases.

### Adding an incident-pack entry

See [docs/incident-pack.md](./docs/incident-pack.md). The short version: a
YAML file under `incidents/`, ID in `UPPERCASE-KEBAB` form, at least one
authoritative reference URL, conservative version pinning.

## Code of Conduct

Be kind. We follow the spirit of the
[Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Report abuse to the email address in [SECURITY.md](./SECURITY.md).

## License

Contributions are licensed under [Apache-2.0](./LICENSE). By submitting a
pull request you agree your contribution will be licensed under those
terms.
