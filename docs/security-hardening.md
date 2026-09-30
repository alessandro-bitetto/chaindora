# Security hardening assessment

Version 0.0.4 implements the audit milestone and follow-up policy/recovery fixes.
The [README](../README.md#gate-command-coverage) states the narrower install contract;
0.0.3 and earlier use the older partial interception behavior.

## Audit fixes

| Audit finding | Implemented control | Regression evidence |
|---|---|---|
| MAL advisories without CVSS could pass default CI | Treat every OSV MAL ID as Critical, including hydration failure | `internal/cli/audit_regression_test.go` |
| npm aliases hid registry identity | Canonical name/version in v1/v2/v3 inventory, gate refs and installed-file checks | `internal/inventory/npm_alias_test.go`, offline CLI alias contract |
| Checked graph/bytes differed from installed graph/bytes | Frozen actual-project lock, digest-authenticated snapshots, offline npm staging, final file/input comparison | `internal/gate/npm_transaction_test.go`, archive regressions |
| Resolution could execute code before approval | No resolver subprocess in the accepted route; unsafe routes explicitly refused | Prepare with nonexistent manager succeeds without executing; real npm lifecycle sentinel |
| Common install/run forms silently bypassed checks | Refuse everything outside frozen npm restores and exact help/version | Dispatcher table tests and manager-double CLI contracts |
| Malformed policy failed open | Strict YAML with known fields, one document, propagated load errors | CLI/gate audit regressions |
| Allow overrides did not match documented semantics | Structured terminal allow/deny, deny precedence, republish guard retained; no cached exceptions | Gate audit regressions |
| Fleet reads exposed findings and inventory | Independent operator credential, disabled unauthenticated enrollment, loopback default, bounded request bodies | Server authentication tests and CLI token-file tests |
| Installed source edits escaped metadata checks | Compare regular files against hash-verified npm artifact manifests; explicit missing-evidence result | Integrity contents tests and CLI clean/tampered/offline contracts |
| Predictive failures disappeared | Structured incomplete-inspection findings; CI exit 2 before fixes/baseline writes | Predictive failure tests and CI coverage contracts |
| CI severity typos silently disabled policy | Validate exact severity lists or standalone `any`/`none` before scanning | CLI invalid-policy regressions and contracts |
| Expired or malformed exceptions hid findings | Enforce UTC expiry dates; reject invalid dates, unknown fields and extra YAML documents | Suppression boundary tests and CLI expired/invalid contracts |
| Fresh-popular checks could ignore offline settings | Apply offline/skip-registry at the heuristic configuration boundary | Zero-request tests for scan, CI and project discovery |
| Missing or broken incident packs disappeared | Report incomplete incident coverage, preserve it in JSON/SARIF and force CI exit 2 | Invalid-record tests and baseline/suppression CLI contracts |
| Concurrent or interrupted installs could lose the previous tree | OS lock inherited by npm; private per-user journal; automatic recovery before preparation | Twelve subprocess-crash scenarios, competing transactions, inherited locks and untrusted-state regressions |

`allow`, lenient and offline policy overrides never relax hash, identity,
transaction-shape or staged-file checks. Static scans validate supplied hashes
(SRI, SHA-256 hex and Go h1); a package check without a project digest cannot
prove it inspected a particular project's artifact. Version/platform hashes can
differ legitimately and require review.

## Validation and efficacy

Run the ordinary race suite, vet, native/cross builds and website build. Run
`python3 tests/offline_cli.py --binary <built-cli> --output <results-dir>` for the
end-to-end JSON/SARIF/exit-code contracts. The frozen npm integration contract is
opt-in with `CHAINDORA_TEST_NPM=<trusted-absolute-npm-path> go test ./internal/gate
-run 'TestNPMFrozenInstall.*RealOffline' -count=1 -v`; it uses generated inert archives,
a local in-process registry substitute and npm offline with lifecycle scripts off.
For enforced network isolation, run `tests/run_environments.py --only frozen-npm
cli --output <results-dir>` using the prepared container toolchains.

The [credential-shape corpus](../testdata/detection/credential-shapes-v1.json)
reports true/false positive counts from versioned
inert fixtures. It establishes expected behavior for those shapes and benign
controls only. Neither that corpus nor the existing resolver/environment matrix
measures recall against real attacks or a representative false-positive rate.
Legacy manager resolver tests remain useful implementation evidence, but do not
mean their install routes are enabled or securely mediated.

## Remaining expansion work

These are unsupported capabilities, not silently accepted install routes:

1. Add equivalent frozen adapters for alternative npm managers, PyPI, NuGet, Go
   and Cargo; prove the requested graph and artifact identity survive installation.
2. Add workspaces, private registries, reviewed build-hook isolation and native
   Windows installation with dedicated integration contracts.
3. Extend installed-file manifests beyond public-registry npm and model legitimate
   generated/native outputs separately from published content.
4. Authenticate provenance signatures, subject digests and trusted builder identities.
5. Build a separately labeled historical attack replay and representative benign
   corpus. Publish measured detection/false-positive rates and evasions; do not
   infer efficacy from passing unit tests.
6. Add richer checked/skipped coverage summaries, including checks with no
   applicable registry signal. Recovery now handles process interruptions;
   full power-loss durability and arbitrary filesystem damage remain outside it.

The [threat model](threat-model.md) documents the trusted local OS/package-manager
assumption, shim bypass, resource limits and the lack of runtime containment.
