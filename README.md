# chaindora

**Supply chain compromise scanner** — detect known IOCs, post-compromise host
artifacts, suspicious dependencies, and rogue install-time code across npm, pip,
GitHub Actions, and other ecosystems.

`chaindora` answers a single question: **"Did I get hit by a supply chain attack?"**

## Status

Phases 1 & 2 complete: project scanning (`chaindora scan`) and host forensics
(`chaindora forensics`) both ship. Behavioral heuristics, static AST scan, CI
gate, and server mode remain on the roadmap.

## Detection layers

1. **Known-IOC matching** — every locked dependency is checked against
   [OSV.dev](https://osv.dev) and a curated incident pack (Shai-Hulud,
   chalk/debug compromise, ctx, ua-parser-js — see [`incidents/`](./incidents/)).
2. **Host-state forensics** — hunts post-compromise artifacts: stored
   credentials in `~/.npmrc`/`~/.pypirc`/`~/.docker/config.json`/
   `~/.aws/credentials`/`~/.gem/credentials`/`~/.cargo/credentials.toml`,
   shell rc tampering (`curl|bash`, `eval $(base64 -d …)`, …), and
   incident-pack file artifacts hunted across `$HOME`.
3. **Behavioral heuristics** *(planned)* — postinstall scripts, freshly
   published versions of popular packages, typosquats, dependency confusion,
   unpinned action refs.
4. **Static AST scan** *(planned)* — eval-of-base64, install-time C2
   exfiltration patterns, hardcoded webhooks.

## Install

```sh
go install github.com/alessandro-bitetto/chaindora/cmd/chaindora@latest
```

## Usage

### Scan a project

```sh
chaindora scan ./my-project
chaindora scan ./my-project --json > findings.json
chaindora scan ./my-project --skip-osv         # incident pack only (offline)
```

### Hunt for post-compromise artifacts on this machine

```sh
chaindora forensics                            # scan $HOME
chaindora forensics --hunt-root ~/code         # narrower artifact hunt
chaindora forensics --skip-hunt                # token + shell rc checks only
```

Exit code is `1` if any finding is reported, `0` if clean.

## Supported ecosystems

| Ecosystem      | Manifests                                                           | Status   |
|----------------|---------------------------------------------------------------------|----------|
| npm            | `package-lock.json` (v1/v2/v3), `yarn.lock` (v1 + Berry), `pnpm-lock.yaml` | done     |
| PyPI           | `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`        | done     |
| GitHub Actions | `.github/workflows/*.yml`                                           | done     |
| RubyGems / crates.io / Go / Maven Central                                            | various  | planned  |

## License

[Apache-2.0](LICENSE)
