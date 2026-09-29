# Troubleshooting

[Documentation](README.md) · [Installation](installation.md) · [CI integration](ci-integration.md)

## `chdora` is not found

Run the executable by its full path first. For Go installations, inspect
`go env GOBIN GOPATH`; for downloaded archives, confirm the extracted directory
containing `chdora` or `chdora.exe` is on PATH. Open a new terminal after changing
persistent PATH settings. Confirm the selected binary with `chdora --version`.

## The gate is installed but a command is not intercepted

On macOS/Linux, run `chdora gate status` and check that `~/.chaindora/bin`
precedes the real managers on PATH. Shell aliases, functions and absolute
manager paths can bypass wrappers. Reinstall the gate after moving the
`chdora` executable, because wrappers contain its resolved path.

On Windows, use `chdora gate exec` directly; automatic wrapper installation is
incomplete. On every platform, consult [command coverage](../README.md#gate-command-coverage):
keeping a manager does not mean every install/restore/build form is gated.

## The gate returns Warn or Unknown

Use `chdora gate check <package>@<version> --ecosystem <ecosystem> --explain`
to inspect available evidence for a package. Accepted ecosystems are `npm`,
`pypi`, `nuget`, `go` and `crates`.

Strict policy refuses both warnings and incomplete checks. `--lenient` permits
warnings; `--allow-offline` separately permits Unknown results and **does not
turn network access off**. Neither option overrides Block. Investigate the
reported registry failure, missing metadata or archive limit before changing
policy. Archive limits can also reject legitimate large packages.

## The scan finds nothing or omits a package

Check that the project contains a [supported inventory format](../README.md#supported-scope).
Manifest fallbacks and existing-state resolvers have less precise coverage than
supported lockfiles. Bun has no lockfile inventory parser, and Deno inventory
covers npm dependencies only.

`--offline`, `--skip-*` flags and directory exclusions reduce coverage. Without
a discoverable incident pack, incident checks do not run; select one with
`--incidents /path/to/incidents`. Many failed predictive checks remain silent.
No findings is not proof that all packages were inspected or that a host is clean.

## CI exits successfully despite findings

`--fail-on` matches the severities you list. `medium` means only Medium;
use `critical,high,medium` for all three. Baselines apply the failure policy
only to fingerprints absent from the saved baseline. Suppressed findings are
removed before policy evaluation, including when their suppression has expired.
An expired suppression warns but continues to apply.

Use `--ignore-suppressions` for an unsuppressed audit and omit `--baseline`
when evaluating the full current findings set. Review [CI policy](ci-integration.md#failure-policy)
before refreshing a baseline or adding exceptions.

## Reports differ from the text display

`--exclude-*` switches hide categories in text output. They do not disable
detectors or remove those findings from JSON/SARIF or the CI failure policy.
Use `--skip-*` only when you intend to reduce inspection.

JSON output is a findings array and may be `null` when empty; JSONL has one
finding per line and may be empty. Neither is a package inventory. Diagnostics
go to stderr, so redirect stdout separately when saving structured reports.

## Report a problem

Include `chdora --version`, OS/architecture, the exact command, expected result
and a minimal lockfile or inert fixture. Remove credentials, private registry
URLs and sensitive report paths before sharing. Use [GitHub issues](https://github.com/alessandro-bitetto/chaindora/issues)
for bugs and [private security reporting](../SECURITY.md) for vulnerabilities in
Chaindora itself.
