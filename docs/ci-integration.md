# CI/CD integration recipes

Drop-in workflow snippets for the major CI platforms. `chdora ci`
autodetects most of these from environment variables, so you usually
don't need to pass any flags beyond the path.

## GitHub Actions

```yaml
# .github/workflows/chdora.yml
name: chdora
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - run: go install github.com/alessandro-bitetto/chaindora/cmd/chdora@latest
      - run: chdora ci . --sarif chaindora.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: chaindora.sarif
```

- `chdora ci` autodetects `$GITHUB_ACTIONS=true` and emits
  `::error file=…,line=…::` annotations on stdout *and* the SARIF
  sidecar.
- `if: always()` ensures the SARIF upload happens even when `chaindora
  ci` exits non-zero (which it will when findings hit the `--fail-on`
  threshold).
- For pull-request-only runs, GitHub Code Scanning will surface the
  annotations inline on the PR diff.

## GitLab CI

```yaml
# .gitlab-ci.yml
chaindora:
  stage: test
  image: golang:1.22
  script:
    - go install github.com/alessandro-bitetto/chaindora/cmd/chdora@latest
    - chdora ci . --format json > chaindora.json
  artifacts:
    when: always
    paths:
      - chaindora.json
    reports:
      sast: chaindora.json
```

- `chdora ci` autodetects `$GITLAB_CI=true`.
- GitLab's SAST report format isn't SARIF-compatible; for now the JSON
  is uploaded as a build artifact. A native GitLab SAST mapping is on
  the roadmap.

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
      - run: chdora ci .
workflows:
  test:
    jobs: [chaindora]
```

Detected via `$CIRCLECI=true`. Default format is `text` — humans read
CircleCI logs more often than dashboards.

## Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
pipelines:
  default:
    - step:
        name: chaindora
        image: golang:1.22
        script:
          - go install github.com/alessandro-bitetto/chaindora/cmd/chdora@latest
          - chdora ci .
```

Detected via `$BITBUCKET_BUILD_NUMBER`. Same text-default behavior.

## Azure Pipelines

```yaml
# azure-pipelines.yml
trigger: [main]
pool:
  vmImage: ubuntu-latest
steps:
  - task: GoTool@0
    inputs:
      version: '1.22'
  - script: |
      go install github.com/alessandro-bitetto/chaindora/cmd/chdora@latest
      chdora ci . --sarif $(Build.ArtifactStagingDirectory)/chaindora.sarif
  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: '$(Build.ArtifactStagingDirectory)'
      artifactName: chaindora
```

Detected via `$TF_BUILD=True`.

## Jenkins

```groovy
// Jenkinsfile
pipeline {
  agent any
  stages {
    stage('chaindora') {
      steps {
        sh 'go install github.com/alessandro-bitetto/chaindora/cmd/chdora@latest'
        sh 'chdora ci . --sarif chaindora.sarif'
        archiveArtifacts artifacts: 'chaindora.sarif', allowEmptyArchive: true
      }
    }
  }
}
```

Detected via `$JENKINS_HOME` or `$BUILD_TAG`.

> **Note**: Jenkins-specific supply-chain risk lives mostly in the
> controller's installed plugins, *not* the `Jenkinsfile`. `chaindora`
> only scans your repo. A Jenkins-controller scanner would be a separate
> tool — see the roadmap.

## Drone / Woodpecker

```yaml
# .drone.yml or .woodpecker.yml
steps:
  - name: chaindora
    image: golang:1.22
    commands:
      - go install github.com/alessandro-bitetto/chaindora/cmd/chdora@latest
      - chdora ci .
```

Detected via `$DRONE=true`. Drone configs are mostly `image:`-based, and
the Docker scanner picks those up automatically.

## Choosing a `--fail-on` threshold

| Threshold | When to use |
|---|---|
| `critical,high` (default) | Most projects. Stops the build for high-confidence findings, lets advisory-class noise through. |
| `any` | Strict gating. Useful for projects with low dependency churn and a culture of triaging every finding. |
| `none` | Informational mode. Always exits 0; use with `--sarif` to feed dashboards without breaking builds. |
| `critical,high,medium` | Reasonable middle ground when behavioral heuristics are well-tuned for your dep tree. |

## Suppressing known false positives

The right place to suppress is in your CI step's grep filter or, better,
in the scanning tool's input — narrow the scan root, exclude a directory
via `--skip-osv` / `--skip-incidents` / `--skip-heuristic`, or fork the
incident pack to your own `--incidents <dir>` path.

A built-in suppressions / ignore-file mechanism is on the roadmap.

## Air-gapped / offline mode

```sh
chdora ci . --skip-osv --skip-heuristic
```

Falls back to incident-pack matching + host forensics (when running
`forensics`). No network calls. Useful for self-hosted runners with
egress restrictions; you'll want to ship the curated incident pack to
the runner's image build.
