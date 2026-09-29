# Contributing to Chaindora

Chaindora focuses on npm, PyPI, .NET/NuGet, Go modules and Rust/crates.io,
including alternative managers within those ecosystems. Shared CI and host
checks remain part of the product.

## Useful contributions

- Reproducible bugs, especially install paths that bypass checks or report
  incomplete inspection as success.
- Safer resolution, exact artifact verification and clearer coverage reporting.
- Parser support for current lockfile formats within the five supported ecosystems.
- Detection rules with inert attack fixtures and representative benign controls.
- Documentation that makes commands, evidence and limitations easier to understand.

Read the [threat model](docs/threat-model.md) and
[security roadmap](docs/security-hardening.md) before proposing a security feature.

## Development

Go 1.22+ is required. The CLI uses Cobra and yaml.v3; justify new dependencies.

```sh
git clone https://github.com/alessandro-bitetto/chaindora.git
cd chaindora
go build -o chdora ./cmd/chdora
go test ./... -race -count=1
go vet ./...
```

Use `gofmt` on changed Go files. Network tests use local HTTP fixtures or
injected probes. Never execute malicious fixture payloads. Include positive
and negative cases for security rules and parser changes. Follow
[contributor notes](CLAUDE.md) for cross-platform paths, gate failures and output.
For website work, follow [website/README.md](website/README.md), build the
production bundle and verify desktop/mobile navigation.

## Incidents and reporting

Package-version malicious-package reports belong in the
[OpenSSF malicious-packages database](https://github.com/ossf/malicious-packages),
which Chaindora queries through OSV. The curated pack covers file artifacts,
shared host evidence and incident-specific investigation instructions. Each
entry needs an authoritative source and conservative matching rules. See the
[incident-pack guide](docs/incident-pack.md).

Report ordinary bugs through GitHub issues with a minimal input and expected
behavior. Report vulnerabilities in Chaindora privately through
[SECURITY.md](SECURITY.md). Be respectful and keep pull requests focused on one
reviewable change. Explain the resulting behavior, testing and limitations.

Contributions are licensed under [Apache-2.0](LICENSE).
