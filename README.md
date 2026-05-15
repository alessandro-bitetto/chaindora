# chaindora

> **Supply chain compromise scanner** — detect known IOCs, post-compromise
> host artifacts, suspicious dependencies, and rogue install-time code across
> npm, pip, six CI/CD platforms, and Docker.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/alessandro-bitetto/chaindora.svg)](https://pkg.go.dev/github.com/alessandro-bitetto/chaindora)

`chaindora` answers one question: **"Did I get hit by a supply chain attack?"**

It runs three commands:

- **`chaindora scan`** — inventories every locked dependency in a project,
  matches them against [OSV.dev](https://osv.dev) and a curated incident
  pack, walks CI YAMLs for compromised actions/orbs/pipes/images, and
  applies behavioral heuristics.
- **`chaindora forensics`** — hunts post-compromise artifacts on the host:
  leaked credentials, shell-rc tampering, and worm-deployed files like
  `shai-hulud-workflow.yml`.
- **`chaindora ci`** — same scan, gated for CI/CD pipelines: autodetects
  GitHub Actions / GitLab / CircleCI / Bitbucket / Azure / Drone / Jenkins,
  applies `--fail-on critical,high`, writes a SARIF sidecar for upload.

## Quick example

```text
$ chaindora scan .
inventoried 142 packages from 11 sources
3 finding(s):

  [CRITICAL] [incident-pack] pkg:npm/%40ctrl/tinycolor@4.1.1
    SHAI-HULUD-2025 — Shai-Hulud npm worm
    source: package-lock.json
    ref: https://socket.dev/blog/shai-hulud-npm-worm

  [HIGH] [osv-ioc] pkg:npm/lodash@4.17.20
    GHSA-35jh-r3h4-6jhm — Command Injection in lodash
    source: package-lock.json

  [MEDIUM] [heuristic:typosquat] pkg:pypi/requets@2.0.0
    HEUR-TYPOSQUAT — PyPI package "requets" is 1 edit(s) away from popular package "requests". Verify this is not a typosquat.
```

## Install

```sh
go install github.com/alessandro-bitetto/chaindora/cmd/chaindora@latest
```

Requires Go 1.22+. Pre-built binaries via `goreleaser` are on the roadmap.

## Commands

### `chaindora scan [path]`

Project-tree scan. Runs OSV.dev queries, incident-pack matching, and
behavioral heuristics by default.

```sh
chaindora scan .                                # scan current directory
chaindora scan ./my-project --format sarif      # SARIF 2.1.0 to stdout
chaindora scan . --skip-osv                     # offline (no OSV queries)
chaindora scan . --fresh-popular                # also check publish dates
chaindora scan . --incidents ./my-incidents     # custom incident pack
```

### `chaindora forensics`

Host-state hunt. Inspects `~/.npmrc` / `~/.pypirc` / `~/.docker/config.json`
/ `~/.aws/credentials` / `~/.gem/credentials` / `~/.cargo/credentials.toml`
for leaked tokens, scans shell rc files for `curl|bash` / `eval $(base64 …)`
patterns, and hunts incident-pack file artifacts (e.g. `shai-hulud-workflow.yml`)
across `$HOME`.

```sh
chaindora forensics                             # scan $HOME
chaindora forensics --hunt-root ~/code          # narrower artifact hunt
chaindora forensics --skip-hunt                 # tokens + shell rc only
chaindora forensics --format json | jq          # pipe to jq
```

### `chaindora ci [path]`

CI gate. Autodetects the running CI from environment variables, picks an
appropriate output format, applies `--fail-on critical,high` by default,
and optionally writes a SARIF sidecar for code-scanning dashboards.

```sh
chaindora ci .                                  # autodetect everything
chaindora ci . --fail-on any                    # strictest gate
chaindora ci . --sarif chaindora.sarif          # also write a sidecar
chaindora ci . --fail-on none                   # informational, always 0
```

A typical GitHub Actions step:

```yaml
- run: chaindora ci . --sarif chaindora.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: chaindora.sarif
```

See [docs/ci-integration.md](./docs/ci-integration.md) for recipes covering
GitLab CI, CircleCI, Bitbucket Pipelines, Azure Pipelines, and Jenkins.

## Detection layers

| Layer | Detector | Highlights |
|---|---|---|
| Known IOC | OSV.dev | Full coverage of npm, PyPI, and OCI (Docker base images); CVSS v3 severity parsing for real-world prioritization |
| Curated incidents | `incident-pack` | Shai-Hulud, qix chalk/debug, ctx PyPI, ua-parser-js, with package-version matches and file-artifact globs. [Contribute new entries.](./docs/incident-pack.md) |
| Host forensics | `hostforensics:*` | Credential files, shell rc tampering, Shai-Hulud workflow files, all incident-pack file artifacts across `$HOME` |
| Heuristics | `heuristic:*` | Unpinned CI refs, `curl\|bash` in CI scripts, npm install scripts, typosquats (Levenshtein vs top-N popular), dependency confusion, fresh-popular versions (opt-in) |

Severity for OSV findings comes from a fully implemented CVSS v3 base-score
calculator (see [internal/osv/cvss.go](./internal/osv/cvss.go)).

## Supported ecosystems

| Ecosystem | Manifests | OSV |
|---|---|---|
| npm | `package-lock.json` (v1/v2/v3), `yarn.lock` (v1 + Berry), `pnpm-lock.yaml` | yes |
| PyPI | `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock` | yes |
| Docker | `Dockerfile`, `docker-compose.yml`, every CI YAML's `image:` field | yes (OCI) |
| GitHub Actions | `.github/workflows/*.yml` | no (incident pack + heuristics) |
| Gitea Actions | `.gitea/workflows/*.yml` | no (incident pack + heuristics) |
| GitLab CI | `.gitlab-ci.yml` (`include:`) | no |
| Bitbucket Pipelines | `bitbucket-pipelines.yml` (`pipe:`) | no |
| CircleCI Orbs | `.circleci/config.yml` (`orbs:`) | no |
| Azure Pipelines | `azure-pipelines.yml` (`task:`) | no |
| Drone / Woodpecker | `.drone.yml` / `.woodpecker.yml` | via Docker `image:` |

Findings normalize to [Package URLs (PURLs)](https://github.com/package-url/purl-spec)
on top of a SARIF-compatible schema.

## Output formats

```sh
chaindora scan . --format text     # human-readable (default)
chaindora scan . --format json     # pretty JSON
chaindora scan . --format jsonl    # one finding per line (for log shippers)
chaindora scan . --format sarif    # SARIF 2.1.0 (GitHub code-scanning et al.)
chaindora scan . --format github   # ::error file=...,line=...:: annotations
```

## Roadmap

- **v0.2** — Static AST scan of installed `node_modules` / `site-packages`
  for install-time exfiltration patterns (eval-of-base64, hardcoded
  webhooks, `child_process` + network in postinstall, …).
- **v0.3** — Server mode: scheduled fleet scans, findings DB, webhook
  ingest.
- **v0.4** — Expanded ecosystems: RubyGems, crates.io, Go modules, Maven
  Central.

## Contributing

The most valuable contribution is **adding entries to the [curated
incident pack](./incidents/)** — see [docs/incident-pack.md](./docs/incident-pack.md)
for the PR flow.

For everything else, see [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security

Found a vulnerability in `chaindora` itself? See [SECURITY.md](./SECURITY.md).

## License

[Apache-2.0](./LICENSE)
