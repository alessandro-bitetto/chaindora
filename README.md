<img src="website/src/assets/logo-symbol.png" width="88" height="88" alt="Chaindora mascot">

# Chaindora

Latest version: **0.0.4**, including the audit hardening and recovery fixes.

**Your code. Your rules.** Supply-chain detection for npm, PyPI, .NET/NuGet,
Go modules and Rust/crates.io, plus verified frozen npm installs. The CLI is `chdora`: one Go binary for macOS, Linux, and Windows.

[Website](https://chaindora.dev) · [Documentation](docs/README.md)
· [Download 0.0.4](https://github.com/alessandro-bitetto/chaindora/releases/tag/v0.0.4)
· [Security reporting](SECURITY.md)

## Start here

Follow the [installation guide](docs/installation.md) for platform downloads,
checksum verification and PATH setup. With a supported Go toolchain (minimum
Go 1.22), install the CLI and fetch its incident data:

```sh
go install github.com/alessandro-bitetto/chaindora/cmd/chdora@v0.0.4
chdora update
chdora scan .
```

Add your Go binary directory to PATH. To build a checkout, run
`go build -o chdora ./cmd/chdora` and use `./chdora`.
`chdora update` refreshes the curated incident pack; it does not upgrade the CLI.

## What you can do

- **Prevent:** `chdora gate exec npm ci` checks an existing lockfile and its
  exact artifacts, installs offline with lifecycle scripts disabled, verifies
  staged files, then replaces `node_modules`.
- **Detect:** `chdora scan .` combines package advisories, incident evidence,
  source heuristics, predictive checks, and npm installed-file verification.
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

Scanning covers five dependency ecosystems. **15 package-manager shim names**
remain recognized, but the install gate currently accepts only frozen npm
restores on macOS/Linux. Other acquisition and execution commands refuse explicitly.

| Ecosystem | Managers | Scan inventory |
|---|---|---|
| npm / JavaScript / TypeScript | npm, Yarn, pnpm, Bun, Deno | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, npm dependencies in `deno.lock` |
| PyPI / Python | pip, pip3, Poetry, uv, Pipenv, PDM | `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pdm.lock`, `pyproject.toml` fallback |
| .NET / NuGet | dotnet, Paket | `packages.lock.json`, `paket.lock`, `.csproj`/`.fsproj`/`.vbproj` fallbacks |
| Go modules | go | `go.mod`, with checksum evidence from `go.sum` |
| Rust / crates.io | Cargo | `Cargo.lock` |

Manifest fallbacks cannot provide the precision of resolved lockfiles; exact
PyPI `==` pins are normalized for version-specific matching. Bun has
no lockfile inventory parser. Deno coverage is for
npm dependencies; raw HTTPS and JSR dependencies are outside the supported scope.

### Gate command coverage

| Command | Behavior |
|---|---|
| `npm ci`, bare `npm install` and their install aliases | Restore an existing v2/v3 `package-lock.json` using verified artifacts; no version resolution or lifecycle scripts |
| Exact `--version`, `-v`, `--help`, `-h` | Uninspected help/version handoff; dry-run never executes it |
| Package additions, updates, `npm run`/`test`, flags before verbs, custom registries, workspaces | Refused before any package-manager subprocess |
| Yarn, pnpm, Bun, Deno, pip/pip3, Poetry, uv, Pipenv, PDM, dotnet, Paket, Go and Cargo commands other than exact help/version | Refused until a verified transaction adapter exists |
| Unknown managers | Refused before binary lookup |

The frozen adapter requires public `https://registry.npmjs.org` artifacts with
lockfile digests. It rejects project `.npmrc`, shrinkwraps, workspace/local/git
links, bundled dependencies and arbitrary npm flags. Only
`--ignore-scripts`, `--no-audit` and `--no-fund` may follow the restore verb.
Bare `npm install` deliberately behaves as `npm ci`: it cannot add or update
packages or rewrite the lockfile. Create and review lockfile changes separately;
that external workflow is outside the gate's protection. Packages requiring
install/build scripts may be unusable after this script-disabled restore.

Gated restores hold a project lock through cleanup. After a process interruption,
the next restore recovers the previous tree or finishes an already-promoted
verified installation using private records in `~/.chaindora/install-transactions`.
Ambiguous states preserve data and refuse recovery; see [troubleshooting](docs/troubleshooting.md).

Automatic shims retain all 15 names to make refusals visible. This is a breaking
change from 0.0.3's partial command interception. `gate check` and scanning still
cover all five registries. Windows supports scanning and package checks; frozen
installation and automatic wrapper installation are not supported there.

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
shims. Frozen installation requires macOS or Linux. Gate options go **before** the manager; package-manager options follow it:

```sh
chdora gate exec --dry-run npm ci
chdora gate check requests@2.32.3 --ecosystem pypi
chdora gate check golang.org/x/text@v0.28.0 --ecosystem go
```

`gate exec --dry-run` verifies and checks the frozen artifacts without executing
a package manager. Registry checks can still use the network.

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

`allow` entries are explicit exceptions to the signal checks and should be
narrowly scoped. Deny entries and changed-integrity history take precedence.
Exceptions never bypass artifact hashes, package identity, transaction validation
or staged-file verification, and are not saved as ordinary cached approvals.
Invalid or unknown configuration fields refuse execution. Cache approvals are
integrity history: current checks rerun every time absent an explicit exception. A changed integrity string
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
exfiltration. Failed predictive inspections emit Low configuration findings with
`CHDORA-PREDICTIVE-INCOMPLETE`; they are no longer silently omitted.

For installed npm v2/v3 lockfiles, published files are compared with manifests
from digest-verified archives. Changed, missing and unexpected files are reported
at their exact paths. Offline verification requires cached artifacts in
`~/.chaindora/artifacts`; missing or unsupported evidence is
`CHDORA-INTEGRITY-INCOMPLETE`. Native/generated files can differ legitimately:
review them rather than treating a mismatch as proof of malware.

CI reports inventory, incident-pack, installed-file and predictive inspection failures in
JSON/SARIF and exits 2 regardless of severity, suppressions or baselines.
Incomplete runs do not apply fixes or update baselines. Explicit `--skip-integrity`
and `--skip-predictive` reduce coverage. Missing, empty or malformed incident packs
fail requested inspection: fetch one with `chdora update`, select one with
`--incidents`, or explicitly disable that layer with `--skip-incidents`.
Offline/skip-registry overrides `--fresh-popular` and its network requests.

Invalid CI `--fail-on` values and malformed suppression files fail before policy
evaluation. Suppression expiry dates must use `YYYY-MM-DD`; expired entries stop
suppressing after that UTC calendar day.

Use `--exclude` for directory basenames. `--skip-*` disables detector work;
`--exclude-*` hides categories in text output, while JSON/SARIF and CI policy
still include them. Consult each command's `--help`
and the [CI guide](docs/ci-integration.md) before setting automated policies.
Fix plans remain reviewable; credential rotation and other sensitive host
changes remain manual. The optional server/agent workflow aggregates fleet
reports; see [architecture](docs/architecture.md) and command help.

## Protection boundaries and next work

The accepted npm path binds inspected bytes to the staged installation and
executes no package code before the verdict. It assumes a trusted local OS,
package manager, lockfile review and operator policy; it is not a runtime sandbox.
PATH shims can be bypassed. The gate cannot make a malicious but correctly hashed
package safe, and script-disabled packages may require a separate reviewed build.

Installed-file verification currently covers public-registry npm v2/v3 lockfiles.
Other ecosystems retain metadata and source checks, not equivalent installed-file
coverage. Provenance is a presence signal, not signature/identity verification.
Static rules do not analyze arbitrary bytecode or every source language, and
synthetic test results do not establish real-world detection rates. See the
[hardening assessment](docs/security-hardening.md) for completed fixes, validation
and the remaining expansion work.

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
