<img src="website/src/assets/logo-symbol.png" width="88" height="88" alt="Chaindora mascot">

# Chaindora

Version **0.0.3**.

**Your code. Your rules.** Supply-chain prevention and detection for npm,
PyPI, .NET/NuGet, Go modules, and Rust/crates.io, including alternative package
managers. The CLI is `chdora`: one Go binary for macOS, Linux, and Windows.

[Website](https://chaindora.dev) · [Documentation](docs/README.md)
· [Download 0.0.3](https://github.com/alessandro-bitetto/chaindora/releases/tag/v0.0.3)
· [Security reporting](SECURITY.md)

## Start here

Follow the [installation guide](docs/installation.md) for platform downloads,
checksum verification and PATH setup. With a supported Go toolchain (minimum
Go 1.22), install the CLI and fetch its incident data:

```sh
go install github.com/alessandro-bitetto/chaindora/cmd/chdora@v0.0.3
chdora update
chdora scan .
```

Add your Go binary directory to PATH. To build a checkout, run
`go build -o chdora ./cmd/chdora` and use `./chdora`.
`chdora update` refreshes the curated incident pack; it does not upgrade the CLI.

## What you can do

- **Prevent:** `chdora gate exec npm install <package>` checks a resolved install
  tree before handing off to the real package manager.
- **Detect:** `chdora scan .` combines package advisories, incident evidence,
  source heuristics, predictive checks, and integrity metadata checks.
- **Investigate:** `chdora audit` combines project discovery and host forensics;
  `chdora forensics` inspects host state. Findings are evidence for review,
  not proof that the machine is clean or compromised.
- **Enforce in CI:** `chdora ci .` supports JSON/SARIF, severity thresholds,
  baselines, suppressions, and PR annotations. See [CI recipes](docs/ci-integration.md).

There is no telemetry. Online checks contact OSV and package registries;
package identities can therefore be disclosed to those services. Fleet reporting
is a separate opt-in workflow. `chdora scan . --offline` disables network-backed
checks, reducing coverage.

## Supported scope

Five dependency ecosystems and **15 package-manager executable names** are supported.
Alternative managers stay within their registry ecosystem; keeping a shim does
not imply coverage of every command or lockfile version.

| Ecosystem | Managers | Scan inventory |
|---|---|---|
| npm / JavaScript / TypeScript | npm, Yarn, pnpm, Bun, Deno | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, npm dependencies in `deno.lock` |
| PyPI / Python | pip, pip3, Poetry, uv, Pipenv, PDM | `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pdm.lock`, `pyproject.toml` fallback |
| .NET / NuGet | dotnet, Paket | `packages.lock.json`, `paket.lock`, `.csproj`/`.fsproj`/`.vbproj` fallbacks |
| Go modules | go | `go.mod`, with checksum evidence from `go.sum` |
| Rust / crates.io | Cargo | `Cargo.lock` |

Manifest fallbacks cannot provide the precision of resolved lockfiles; exact
PyPI `==` pins are normalized for version-specific matching. Bun has
an install resolver but no Bun lockfile inventory parser. Deno coverage is for
npm dependencies; raw HTTPS and JSR dependencies are outside the supported scope.

### Gate command coverage

This is the current dispatcher, not a promise of complete mediation. Explicit
package requests are checked for the following forms:

| Manager | Recognized forms |
|---|---|
| npm | `install`, `i`, `add`; `update`, `up`, `upgrade` |
| Yarn | `add`; `upgrade`, `upgrade-interactive`, `up` |
| pnpm | `add`; `update`, `up`, `upgrade` |
| Bun | `add`, `install`, `i` |
| pip / pip3 | `install`, including `--upgrade` |
| Poetry | `add`, `update` |
| uv | `add`, `lock` |
| Pipenv | `install` |
| PDM | `add` |
| dotnet | `add package` |
| Go | `get`, `install` |
| Cargo | `add`, `install`, `update` |
| Deno | `cache`, `add`, `install` dispatch to a resolver of existing project state |
| Paket | `install`, `update`, `restore` inspect the existing `paket.lock` |

Bare update-all resolution exists for npm, Yarn, pnpm and Cargo. Other recognized
bare update verbs are refused when no update-all resolver exists. Deno and Paket
operate on existing project state: they do not reliably model a newly requested
dependency or subsequent update. Deno 2 resolves existing project dependencies
without a local `node_modules` directory; npm entries in lockfile versions 3–5
are understood. Empty or failed resolutions refuse installation.

**Known gaps:** bare installs such as `npm install`, `npm ci`, `uv pip install`,
`uv sync`, restore/build/run commands, and unrecognized verbs can pass through
ungated. Flags before verbs and flags-only forms also need better coverage.
Recognized commands can still have resolver limitations. Use the
[threat model](docs/threat-model.md) when deciding where to rely on the gate.

Dependency registries outside this scope are unsupported. Explicit `gate exec`
requests for other managers are refused. Gate installation writes wrappers only
for the managers listed above.

Shared GitHub/GitLab/Gitea Actions, CircleCI, Bitbucket, Azure Pipeline and
Docker-reference checks remain, along with host persistence, trust-anchor,
credential, browser and IDE checks. OS package enumeration in deep host
forensics is host evidence, not an additional supported install ecosystem.

## Prevention

```sh
chdora gate install                # macOS/Linux: shims and a marked shell PATH block
chdora gate status                 # inspect activation
chdora gate install --no-persist   # shims only; print PATH setup
chdora gate disable                # remove managed shims and shell block
```

Open a new terminal after installation. Shims live in `~/.chaindora/bin`;
they need to precede the real managers on PATH. Direct invocation works without
shims. On Windows, use `chdora gate exec` directly: automatic wrapper installation
is incomplete. Gate options go **before** the manager; package-manager options follow it:

```sh
chdora gate exec --dry-run npm install lodash@4.17.21
chdora gate check requests@2.32.3 --ecosystem pypi
chdora gate check golang.org/x/text@v0.28.0 --ecosystem go
```

`gate exec --dry-run` never hands off the final command, including commands that
would otherwise pass through ungated. Resolution still invokes a package manager.

Versions here illustrate syntax, not safety recommendations.

The gate checks known-malicious OSV entries, release cooldown (72 hours by
default), allow/deny rules, publisher changes, maintainer history, source
patterns, version differences, git URLs and available provenance signals.
Signal availability varies by registry. Provenance presence is not cryptographic
verification. Age and popularity do not prove a package safe.

Strict policy refuses Block, Warn and Unknown. `--lenient` permits warnings;
`--allow-offline` separately permits incomplete checks and does **not** disable
network access. A Block result still refuses the install. Project configuration
is loaded from `chaindora.yml` (or its supported dotfile/YAML variants), walking
up from the current directory:

```yaml
cooldown_hours: 72
allow_on_warn: false
allow_on_unknown: false
deny:
  npm:
    - "example-untrusted-package"
```

`allow` entries bypass checks and should be narrowly scoped. Cache approvals are
integrity history: current checks rerun every time. A changed integrity string
for a previously approved version triggers republish review. Missing hashes
prevent that comparison; legitimate platform artifacts can also differ.
`chdora gate cache clear` removes that evidence.

## Detection and investigation

```sh
chdora scan . --format json
chdora scan . --offline
chdora audit --git-only
chdora forensics --deep
chdora ci . --fail-on critical,high,medium
```

Detection combines OSV advisories, curated incident indicators, source patterns,
lockfile/name/version drift, release-history signals and host checks. Dedicated
JavaScript/TypeScript and Python rules flag bulk environment serialization or
credential-file reads combined with outbound HTTP. They run independently of
version differences, so unchanged suspicious behavior is still inspected.

Findings include severity, confidence and evidence. Predictive credential hits
are High severity / Medium confidence: a suspicious combination, not proven
exfiltration. Failed credential inspection emits a Low configuration finding;
several other incomplete predictive checks still produce no finding.

CI reports failed inventory parsing as `CHDORA-INVENTORY-INCOMPLETE` in JSON and
SARIF and exits 2, regardless of severity policy, suppressions or baselines.
Incomplete runs do not apply fixes or update baselines.

Use `--exclude` for directory basenames. `--skip-*` disables detector work;
`--exclude-*` hides categories in text output, while JSON/SARIF and CI policy
still include them. Consult each command's `--help`
and the [CI guide](docs/ci-integration.md) before setting automated policies.
Fix plans remain reviewable; credential rotation and other sensitive host
changes remain manual. The optional server/agent workflow aggregates fleet
reports; see [architecture](docs/architecture.md) and command help.

## Protection boundaries and next work

Chaindora reduces risk; it is **not a sandbox, antivirus replacement or guarantee
against compromise**. Resolution can execute package-manager/plugin/build code.
The eventual install is not yet bound to the exact artifacts checked. Static
rules do not analyze arbitrary bytecode or every source language. Installed
integrity checks do not recompute all file contents against verified artifacts.

The next priorities are exact install-transaction binding, safe resolution,
complete install/restore coverage, installed-file verification and authenticated
provenance. Concrete gaps and acceptance tests are in the
[security roadmap](docs/security-hardening.md). Depth in the five supported
ecosystems comes before new integrations.

## Development

```sh
go test ./... -race
go vet ./...
go build ./cmd/chdora
cd website
npm ci
npm run build
```

See [architecture](docs/architecture.md), [contributor notes](CLAUDE.md),
[incident-pack guide](docs/incident-pack.md), and [website development](website/README.md).
For operational help, start at the [documentation index](docs/README.md) or
[troubleshooting guide](docs/troubleshooting.md).
Licensed under [Apache-2.0](LICENSE).
