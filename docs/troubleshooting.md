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

Windows scanning and `gate check` remain available, but frozen installs and
automatic wrappers are unsupported. On macOS/Linux only frozen npm restores
are accepted; the other manager shims deliberately refuse acquisition/run/build
commands. Consult [command coverage](../README.md#gate-command-coverage).

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
a usable incident pack, the scan reports `CHDORA-INCIDENTS-INCOMPLETE`; `scan`
and `ci` exit 2. Fetch one with `chdora update`, select one with
`--incidents /path/to/incidents`, or explicitly use `--skip-incidents` to remove
this coverage. Failed predictive checks also produce incomplete-inspection findings.
No findings is not proof that all packages were inspected or that a host is clean.

## CI exits successfully despite findings

`--fail-on` matches the severities you list. `medium` means only Medium;
use `critical,high,medium` for all three. Baselines apply the failure policy
only to fingerprints absent from the saved baseline. Active suppressions remove
matching findings before policy evaluation. Expired suppressions are ignored
with a warning; their findings return to policy and baseline evaluation.
Expiry dates are inclusive through the end of that UTC day. Invalid policy
tokens, suppression dates, unknown YAML fields and extra documents fail the run.

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

## Offline CI cannot verify installed npm files

Online scans and frozen npm installs cache verified artifacts in
`~/.chaindora/artifacts`. Offline runs rehash these bytes against the lockfile
before comparing installed files. Populate that cache in a trusted online step
and retain it for the same lockfile. Missing/invalid artifacts produce
`CHDORA-INTEGRITY-INCOMPLETE` and CI exit 2; `--fail-on none`, suppressions and
baselines do not waive an incomplete run. `--skip-integrity` explicitly removes
this check and its protection.

Generated/native build outputs can differ from the published archive. Review
these mismatches and build requirements; do not assume every mismatch is malware.

## A frozen npm install was interrupted or is already running

Retry the same gated restore. Before preparing a new install, Chaindora obtains
the project lock and recovers an interrupted swap: it restores the previous tree
or completes a verified replacement that is already visible. Recovery records
live in `~/.chaindora/install-transactions`; repository files cannot supply them.

If another Chaindora process or its surviving npm child holds the lock, wait for
it to finish. The `.chaindora-install.lock` file remains after exit by design;
its presence does not mean a process is running. Do not delete it to bypass a
live lock. If recovery reports an ambiguous state, preserve the journal and
staging/backup directories for review. This handles process interruptions;
arbitrary filesystem damage or sudden power loss is not covered by that guarantee.

## Fleet dashboard asks for credentials

Use username `viewer` and the contents of the server's `read-token` file as the
password. The default file is `~/.chaindora/server/read-token`; an explicit
`--data-dir` or `--read-token-file` changes its location. API reads accept the
same token in a Bearer header. Enrollment secrets and agent credentials cannot
read fleet data. Keep the file private (0600 on Unix), and use TLS for remote access.
