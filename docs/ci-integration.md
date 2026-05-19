# CI/CD integration recipes

Drop-in snippets for the major CI platforms. `chdora ci` autodetects
most of them from environment variables, so you usually don't need
extra flags.

## Quality-gate features (v0.10+)

Beyond basic scanning, `chdora ci` exposes three CI-focused features
designed to make it work as a PR gate rather than a noisy report:

| Feature | Flag | What it does |
|---|---|---|
| **Baseline mode** | `--baseline path.json` | First run records fingerprints; subsequent runs apply `--fail-on` only to NEW findings. Pre-existing tech debt doesn't break every PR. Combine with `--update-baseline` after intentional resolution. |
| **Suppression file** | `.chaindora-ignore.yml` | Per-project ignore list. Each entry MUST have a `reason`. Optional `expires: YYYY-MM-DD` (expired entries still apply but warn). |
| **PR-comment markdown** | `--format pr-comment` or `--pr-comment <file>` | Sticky-comment-marker output for GitHub PR flows. Severity-colored cards + new-since-baseline section + collapsible suppressed/pre-existing. |

## Predictive findings in CI (v0.15+)

The predictive detector (gate-style behavioral checks replayed
against installed packages) emits findings at three severity tiers:

| Checker | Severity | Notes |
|---|---|---|
| `republish-guard` | Critical | Hard tamper signal — fires when a `name@version` reappears with different bytes |
| `cooldown` / `version-diff` | Medium | Real time-sensitive / behavioral signals |
| `publisher-change` / `maintainer-trust` / `provenance` | Low | Advisory — high signal-to-noise per finding, mostly informational |

**Default `--fail-on=critical,high` skips all advisory predictive
findings.** You only fail the build on real republish-guard hits.

To make predictive `cooldown` + `version-diff` block PRs:
```sh
chdora ci . --fail-on critical,high,medium
```

To skip the predictive detector entirely in CI (saves the registry
round-trips, halves the scan time):
```sh
chdora ci . --skip-predictive
```

To hide the predictive section from the rendered output without
disabling the detector (still flows into JSON / SARIF):
```sh
chdora ci . --exclude-predictive
```

## GitHub Actions

### Quick start — SARIF + PR annotations

```yaml
# .github/workflows/chaindora.yml
name: chaindora
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # upload-sarif requires this
      contents: read
    steps:
      - uses: actions/checkout@v4
      - run: |
          curl -L https://github.com/alessandro-bitetto/chaindora/releases/latest/download/chaindora_0.16.0_linux_amd64.tar.gz | tar xz
          sudo mv chdora /usr/local/bin/
      - run: chdora ci . --sarif chaindora.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: chaindora.sarif
```

`chdora ci` autodetects `$GITHUB_ACTIONS=true` and emits inline
`::error file=…,line=…::` annotations on stdout alongside the SARIF
sidecar. `if: always()` ensures the upload step runs even when chdora
exits non-zero.

### SonarQube-grade: baseline + suppression + sticky PR comment

```yaml
- run: chdora ci . \
    --baseline ./.chdora-baseline.json \
    --pr-comment ./chdora-comment.md \
    --sarif chaindora.sarif \
    --fail-on critical,high

- name: Sticky PR comment
  if: github.event_name == 'pull_request' && always()
  uses: marocchino/sticky-pull-request-comment@v2
  with:
    path: ./chdora-comment.md

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: chaindora.sarif
```

`chdora-comment.md` is GitHub-flavored markdown with the sticky-comment
marker `<!-- chaindora:pr-comment -->`. The sticky-pull-request-comment
action looks for that marker and updates in place across pushes — one
PR comment, not 47.

### Baseline workflow

```sh
# Once per repo, after the first scan stabilizes:
chdora ci . --baseline ./.chdora-baseline.json --update-baseline
git add .chdora-baseline.json
git commit -m "chore: seed chaindora baseline"
```

Subsequent PRs only fail on findings *introduced by the PR*. Tech
debt sits in the baseline; a follow-up PR can refresh:

```sh
chdora ci . --baseline ./.chdora-baseline.json --update-baseline
```

### Suppression file

`chaindora-ignore.yml` at the repo root (or any parent of the scan
path) — chdora walks up like `.gitignore`:

```yaml
suppress:
  - vuln_id: GHSA-xxxx-yyyy-zzzz
    package: some-package
    reason: "Accepted risk per security review; tracked in JIRA-1234"
    expires: 2026-12-31

  - fingerprint: 5f3a92...   # from `chdora scan --format json | jq .[].fingerprint`
    reason: "Test fixture, not production"
```

Every entry requires `reason` — the parser refuses silent suppression.

## GitLab CI

```yaml
# .gitlab-ci.yml
chaindora-scan:
  image: golang:1.22
  script:
    - go install github.com/alessandro-bitetto/chaindora/cmd/chdora@latest
    - chdora ci . --format json > chaindora.json --sarif chaindora.sarif
  artifacts:
    when: always
    paths:
      - chaindora.json
    reports:
      sast: chaindora.sarif
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

`chdora ci` detects `$GITLAB_CI=true` and chooses text output by
default; we override to JSON above for artifact archival. The SARIF
sidecar uploads as a GitLab SAST report.

## CircleCI

```yaml
# .circleci/config.yml
version: 2.1
jobs:
  chaindora:
    docker:
      - image: cimg/go:1.22
    steps:
      - checkout
      - run: go install github.com/alessandro-bitetto/chaindora/cmd/chdora@latest
      - run: chdora ci . --sarif chaindora.sarif
      - store_artifacts:
          path: chaindora.sarif
workflows:
  build:
    jobs:
      - chaindora
```

`$CIRCLECI=true` is autodetected.

## Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
image: golang:1.22

pipelines:
  default:
    - step:
        name: chaindora
        script:
          - go install github.com/alessandro-bitetto/chaindora/cmd/chdora@latest
          - chdora ci . --format json > chaindora.json
        artifacts:
          - chaindora.json
```

`$BITBUCKET_BUILD_NUMBER` (any non-empty value) triggers Bitbucket-
appropriate output formatting.

## Azure Pipelines

```yaml
# azure-pipelines.yml
trigger: [main]

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: GoTool@0
  inputs:
    version: '1.22'
- script: |
    go install github.com/alessandro-bitetto/chaindora/cmd/chdora@latest
    chdora ci . --sarif $(Build.ArtifactStagingDirectory)/chaindora.sarif
- task: PublishBuildArtifacts@1
  condition: always()
  inputs:
    pathToPublish: $(Build.ArtifactStagingDirectory)
    artifactName: chaindora
```

`$TF_BUILD=True` is the autodetect signal.

## Drone / Woodpecker

```yaml
# .drone.yml
kind: pipeline
type: docker
name: chaindora
steps:
  - name: scan
    image: golang:1.22
    commands:
      - go install github.com/alessandro-bitetto/chaindora/cmd/chdora@latest
      - chdora ci . --format json > chaindora.json
```

`$DRONE=true` triggers Drone-appropriate output.

## Jenkins

```groovy
// Jenkinsfile
pipeline {
  agent any
  stages {
    stage('chaindora') {
      steps {
        sh '''
          go install github.com/alessandro-bitetto/chaindora/cmd/chdora@latest
          chdora ci . --sarif chaindora.sarif --format json > chaindora.json
        '''
        archiveArtifacts artifacts: 'chaindora.sarif,chaindora.json', fingerprint: true
      }
    }
  }
}
```

`$JENKINS_HOME` or `$BUILD_TAG` is the autodetect signal.

## Server / fleet mode (v0.13+)

If you're running `chdora server` to aggregate findings across an org,
the CI step can push directly:

```yaml
# GitHub Actions: enroll the CI as an agent, then push every run
- run: |
    chdora agent enroll \
      --server https://chaindora.corp:8080 \
      --name ci-${{ github.repository }}-${{ github.workflow }} \
      --enrollment-secret ${{ secrets.CHAINDORA_ENROLL }}
    chdora scan . --format json > findings.json
    chdora agent push --findings findings.json
```

The findings land in the fleet dashboard's recent-findings table and
contribute to the per-repo severity counts. Use `--name` carefully —
the agent identity persists across runs only if you give it a stable
name.

For continuous-mode CI nodes (always-on builders), pair `chdora watch`
with the enrolled agent to push every interval rather than every CI
run.

## `--fail-on` thresholds

| Value | Meaning |
|---|---|
| `critical,high` (default) | Exit 1 on CRITICAL or HIGH findings |
| `any` | Exit 1 on any finding regardless of severity |
| `none` | Always exit 0 — informational mode |
| Custom (e.g. `medium`) | Exit 1 on MEDIUM-or-above |

Combined with `--baseline`, the threshold applies to the NEW findings
only — pre-existing tech debt doesn't fail the PR.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings at or above `--fail-on` (after baseline + suppression) |
| 1 | At least one finding at the threshold |
| 2 | Cobra-level error (bad flags, missing files) |

## Common debugging

```sh
# Inspect the parsed inventory without running detectors
chdora scan . --skip-osv --skip-incidents --skip-heuristic --format json | jq

# Run baseline mode dry-run — see what would be NEW without writing
chdora ci . --baseline /tmp/dummy.json --format json

# Print the rendered PR comment locally before pushing
chdora ci . --baseline ./.chdora-baseline.json --format pr-comment | less

# See which CI env chdora detected
chdora ci . --verbose 2>&1 | grep "detected env"
```

## Pointers

- Configuration schema: [README.md](../README.md)
- Server mode: [docs/architecture.md](./architecture.md)
- Threat model: [docs/threat-model.md](./threat-model.md)
- Underlying gate stack: [docs/architecture.md](./architecture.md)
