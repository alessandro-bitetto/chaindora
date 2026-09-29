# CI integration

[Documentation](README.md) · [Installation](installation.md) · [Troubleshooting](troubleshooting.md)

`chdora ci` scans a project and applies a finding policy. It does not intercept
package installation in the CI job. Run it against the lockfiles and source you
intend to build, and review the [protection boundaries](threat-model.md).

## Failure policy

```sh
chdora ci . --fail-on critical,high --sarif chaindora.sarif
```

| `--fail-on` | Findings that cause exit 1 |
|---|---|
| `critical,high` (default) | Critical or High |
| `critical,high,medium` | Critical, High or Medium |
| `medium` | Medium only |
| `any` | Any severity |
| `none` | No failure based on findings; operational errors still fail |

The list matches exact severities; it is not a minimum severity. Spell levels
as `critical`, `high`, `medium`, `low` or `unknown`. Unrecognized tokens do not
match a finding, so review policy values carefully.

Suppressions are applied first. When `--baseline` is supplied, the policy then
applies only to findings whose fingerprints are absent from that baseline.
This is a comparison with a saved report, not analysis of a Git diff.

| Exit code | Meaning |
|---|---|
| 0 | No unsuppressed, new finding matches the policy |
| 1 | At least one unsuppressed, new finding matches the policy |
| 2 | Command, input, configuration or operational error |

Unreadable inventory files and lockfile parsing failures emit
`CHDORA-INVENTORY-INCOMPLETE` in JSON/SARIF and force exit 2. These coverage
failures cannot be waived with `--fail-on none`, suppressions or a baseline.
The incomplete run does not apply fixes or update the baseline; valid findings
from the rest of the project are still reported.

With no baseline, every unsuppressed finding is considered new. A successful
exit does not guarantee complete inspection; some skipped or failed checks
produce no findings.

## Predictive findings

| Check | Severity | Interpretation |
|---|---|---|
| `republish-guard` | Critical | An observed integrity string changed for the same package/version; investigate artifact and platform identity |
| `credential-exfiltration` | High | Credential collection plus outbound HTTP in npm/PyPI source; Medium confidence, not proof of exfiltration |
| `cooldown`, `version-diff` | Medium | Recent release or suspicious pattern changes |
| `publisher-change`, `maintainer-trust`, `provenance` | Low | Supporting registry metadata |
| Incomplete credential inspection | Low, configuration category | The requested source inspection failed |

The default policy can fail on both republish and credential-collection findings,
as well as Critical/High findings from other detectors. Most other predictive
Unknown results are suppressed. `--skip-predictive` disables those checks;
`--exclude-predictive` only hides their text-output section. Category display
filters do not remove results from JSON/SARIF or the CI failure policy.

## GitHub Actions

This workflow installs the pinned CLI with Go, fetches the incident pack, scans
the checkout and uploads SARIF even when findings fail the scan step. Save it as
`.github/workflows/chaindora.yml` in the project being scanned.

```yaml
name: chaindora
on: [push, pull_request]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
      - uses: actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c # v6.4.0
        with:
          go-version: stable
          cache: false
      - name: Install Chaindora
        run: |
          go install github.com/alessandro-bitetto/chaindora/cmd/chdora@v0.0.3
          chdora update --dest "$RUNNER_TEMP/chaindora-incidents"
      - name: Scan
        run: |
          chdora ci . --incidents "$RUNNER_TEMP/chaindora-incidents" --sarif chaindora.sarif
      - name: Upload SARIF
        if: always() && hashFiles('chaindora.sarif') != ''
        uses: github/codeql-action/upload-sarif@8aad20d150bbac5944a9f9d289da16a4b0d87c1e # v4.36.2
        with:
          sarif_file: chaindora.sarif
```

The action revisions above are the ones used by this repository's test workflow.
Review action updates through your dependency-maintenance process. For a fixed
incident snapshot, select a reviewed incident directory from the release archive
instead of running `chdora update` against the current upstream pack.

GitHub Actions is autodetected through `GITHUB_ACTIONS=true`; its default output
uses workflow annotations. SARIF upload additionally requires code scanning to
be available for the repository and appropriate token permissions. See
[GitHub's SARIF upload guide](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
for repository and workflow requirements.

### Baseline workflow

First review the full findings report. To record an accepted baseline explicitly:

```sh
chdora ci . --baseline .chdora-baseline.json --update-baseline --fail-on none
```

Review and commit the generated file with your policy change. Normal runs use:

```sh
chdora ci . --baseline .chdora-baseline.json --sarif chaindora.sarif
```

A missing baseline does **not** get created automatically: every current finding
is new until `--update-baseline` writes the file. Updating the baseline does not
change the current run's failure decision, which uses the previously loaded
baseline. `--fail-on none` above makes the intentional acceptance run independent
of finding severity while preserving operational errors.

Fingerprints use detector, advisory ID, PURL and source path. They do not include
all evidence or severity fields; an existing fingerprint can acquire new evidence
without becoming new to the baseline. Keep scan paths consistent and periodically
review the full findings set without baseline filtering.

### Suppressions

Place `.chaindora-ignore.yml` at the scan root or an ancestor:

```yaml
suppress:
  - vuln_id: GHSA-example-advisory
    package: example-package
    version: "1.2.3"
    reason: "Accepted by the project security review; tracked in issue 123"
    expires: "2026-12-31"
```

Replace the illustrative identity with an actual finding. `reason` is mandatory;
`package` and exact `version` narrow an advisory match. An exact `fingerprint`
can be used instead of `vuln_id`. Obtain it from the finding's SARIF
`partialFingerprints.primaryLocationLineHash`; ordinary findings JSON does not
contain a `fingerprint` field.

Discovery also recognizes `.chaindora-ignore.yaml` and `chaindora-ignore.yml`.
In 0.0.3, `--suppress-file` is passed to directory discovery, so use the default
filename and directory placement rather than relying on arbitrary file paths.
Expired suppressions **continue to suppress** and emit a warning. Use
`--ignore-suppressions` for a full audit.

### Markdown reports for pull requests

```sh
chdora ci . --baseline .chdora-baseline.json --pr-comment chdora-comment.md --sarif chaindora.sarif
```

This writes a Markdown file; it does not post to GitHub. `--format pr-comment`
writes the report to stdout instead. A separate, explicitly configured publishing
step can use the file. That step needs its own PR-write permission and must handle
fork-PR restrictions. Keep credentials and sensitive paths out of public reports.

## GitLab CI

This example gates the job and preserves JSON/SARIF as downloadable artifacts.
It assumes a Go-capable runner image; pin that image to a reviewed version or
digest according to your project's build policy.

```yaml
chaindora-scan:
  image: golang:1
  script:
    - go install github.com/alessandro-bitetto/chaindora/cmd/chdora@v0.0.3
    - chdora update --dest /tmp/chaindora-incidents
    - chdora ci . --incidents /tmp/chaindora-incidents --format json --sarif chaindora.sarif > chaindora.json
  artifacts:
    when: always
    paths:
      - chaindora.json
      - chaindora.sarif
```

SARIF is not GitLab's native SAST JSON schema. For security-dashboard ingestion,
use GitLab's `artifacts:reports:sarif` support where available, following its
[report-type documentation](https://docs.gitlab.com/ci/yaml/artifacts_reports/).
GitLab ingests security findings only from a successful producing job; a failing
policy job should remain separate from a report-ingestion job. The example above
uses ordinary artifacts and retains the scan's failure status.

## Other CI systems

Install 0.0.3 using the [installation guide](installation.md), select incident
data, and run the same command in CircleCI, Bitbucket, Azure Pipelines, Drone or
Jenkins:

```sh
chdora ci . --incidents /path/to/incidents --format json --sarif chaindora.sarif > chaindora.json
```

Configure the platform's artifact publication to run even when the scan fails.
Keep the original scan exit code; appending `|| true` would disable the finding
gate. Pin the scanner installation independently of the application's toolchain.

Autodetection changes the default output format, not the detection policy:

| Environment | Detection variable | Default output |
|---|---|---|
| GitHub Actions | `GITHUB_ACTIONS=true` | GitHub annotations |
| GitLab | `GITLAB_CI=true` | Text |
| CircleCI | `CIRCLECI=true` | Text |
| Bitbucket | nonempty `BITBUCKET_BUILD_NUMBER` | Text |
| Azure Pipelines | `TF_BUILD=True` | Text |
| Drone | `DRONE=true` | Text |
| Jenkins | nonempty `JENKINS_HOME` or `BUILD_TAG` | Text |
| Other runners | none of the above | Text |

## Output and diagnostics

Use `--format json` for a findings array, `--format jsonl` for individual records,
or `--sarif path` for a separate SARIF report. An empty JSON result can be `null`;
JSONL can be empty. These outputs contain findings, not the full dependency inventory.

```sh
# Local checks only; network-backed coverage is disabled.
chdora ci . --offline --verbose --format json > chaindora.json

# Review all current findings independently of baseline/suppression policy.
chdora ci . --ignore-suppressions --fail-on none --format json > review.json
```

The second command omits `--baseline` intentionally. Diagnostics go to stderr.
See the [finding schema](schema/v1/finding.schema.json) for record fields and
[troubleshooting](troubleshooting.md) for common configuration mistakes.
