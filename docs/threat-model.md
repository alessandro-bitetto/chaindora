# Threat model

This document is chaindora's permanent reference for **what a supply-chain
attack is, where it can happen, and what we do (or don't) cover**. The
roadmap follows from this, not the other way around.

A supply-chain attack is anywhere code or trust enters your boundary
from outside. It's larger than "compromised npm package" — every layer
of build, deploy, and runtime has its own attack surface and its own
trust model.

---

## 1. The four dimensions

Every concrete supply-chain attack maps to a point in this four-dimensional
space. When we evaluate "is chaindora doing enough?" we evaluate per-dimension,
not per-package-manager.

| Dimension | Question it answers |
|---|---|
| **Code-entry vector** | *Where* did the bytes physically come from? |
| **Code-execution moment** | *When* during the lifecycle does the attacker's code actually run? |
| **Trust-anchor** | *What* would the attacker have to compromise to invalidate every other check? |
| **Adjacent surfaces** | Related boundaries (identity, IaC, ML weights) that share the same trust-shaped problem |

Real attacks usually combine dimensions. shai-hulud was code-entry=npm-registry +
execution=postinstall. xz-utils was code-entry=source-tarball-replaced +
execution=build-time-link-into-sshd + trust-anchor=long-trust-maintainer-account.

---

## 2. Code-entry vectors

Where bytes physically arrive on your machine. Lower in the table = lower
trust model = harder to gate.

| Vector | Trust model | Coverage |
|---|---|---|
| Language registry (npm, PyPI, crates, RubyGems, Maven Central, …) | Centralized, often signed | ✅ npm full; PyPI partial; others planned |
| OS package manager (apt, brew, dnf, pacman, …) | Signed by distro key | partial — `forensics --deep` enumerates, no gate |
| Container registry (Docker Hub, ghcr.io, ECR, …) | Optional signing (Notary, cosign) | partial — image refs detected, no gate |
| Direct git URL (`go get gh.com/x`, `pip install git+`, `npm install user/repo`, CMake `FetchContent_Declare`, Cargo `git = "..."`) | **No registry, no signing, no provenance** | **uncovered** — biggest no-registry gap |
| HTTP archive in build scripts (Makefile `wget`, Dockerfile `RUN curl`) | URL-pinned bytes, optional `sha256sum` | partial — `heuristic:cishell` flags curl-pipe-shell |
| Git submodules / subtrees | Inherits upstream's compromise | **uncovered** |
| Git LFS pointers | LFS server is a separate trust boundary | **uncovered** |
| Vendored copies in own repo | Frozen but never updated | not a chaindora job |
| AI model weights (HuggingFace, TF Hub, PyTorch Hub) | Often pickle → RCE on load | **uncovered** |
| OAuth-driven SaaS sync (Vercel deploy hook, Render build, …) | Trusts SaaS infra | partly out-of-scope |
| Build-time codegen inputs (openapi specs, protobuf, GraphQL schemas pulled from URLs) | Same trust as the URL | **uncovered** |
| Browser CDN imports (`<script src="cdn.example.com/...">`) | Runtime fetch, no install | **uncovered** |

**Pattern**: anything in the "uncovered" rows that doesn't go through a
registry needs a different verification model — URL trust evaluation,
git-ref signing, content-hash pinning. The same gate framework still
applies (cooldown → static-pattern → publisher-change) but the inputs
change.

---

## 3. Code-execution moments

The same byte-stream can be benign at one moment and dangerous at another.
This dimension is the one most discussions miss. Each moment is a separate
attack surface even for the same package.

| Moment | Examples per ecosystem | Coverage |
|---|---|---|
| **Install time** | npm postinstall; pip `setup.py`; Cargo build.rs; RubyGems extensions; Conan recipes; Cargo `proc-macro`s | partial — npm/PyPI static-scan |
| **Build time** | Source generators (.NET, Rust proc-macros, Java annotation processors); protoc plugins; openapi codegen; Bazel rules; Gradle plugins; Cargo `build.rs` again | **uncovered** |
| **Import time** | Go `init()` functions; Python module-level code; JS top-level await; Java static initializers; OCaml functor evaluations | **uncovered** |
| **Tool invocation** | pre-commit hooks; husky / lefthook git hooks; lint-staged configs; format-on-save extension plugins | **uncovered** |
| **Test time** | Test fixtures that hit the network; integration-test setup that runs as user | **uncovered** |
| **Editor open time** | VS Code `tasks.json` auto-run; IntelliJ run configs in repo; devcontainer features | partial — extensions inventoried, not configs |
| **Shell entry** | `.envrc` (direnv); oh-my-zsh plugins; shell rc tampering | partial — `hostforensics:shellrc` |
| **Deploy time** | Helm hooks; Terraform `provisioner "local-exec"`; Ansible playbooks; CI deploy scripts | **uncovered** |
| **Runtime** | LD_PRELOAD; Istio/Linkerd/Dapr sidecars; APM agents; JVM `-javaagent:` | **out of scope** — runtime-monitoring tools (Falco, Tetragon) own this |
| **Update time** | Sparkle, Squirrel, Electron auto-updaters; `brew update` git pull; `chdora upgrade` itself | partial — chdora self-update is sumcheck-verified |

**Why this dimension matters.** A package can pass every install-time
check and still execute attacker code at `cargo build` (proc-macro),
`go build` (init), `dotnet build` (source generator), or `helm install`
(chart hook). The gate framework needs per-moment static analyzers,
not just install-script scanning.

---

## 4. Trust-anchor vectors

If the attacker compromises one of these, every other check becomes
worthless. Highest-leverage targets — but also lowest-frequency in
the real-world data we have.

| Anchor | What it controls | Compromise looks like | Coverage |
|---|---|---|---|
| TLS root CA store | All HTTPS verification | New CA installed without IT approval | **uncovered** |
| OS keychain / Credential Manager | All saved tokens | Drift in entries | partial — `hostforensics:tokens` |
| GPG keyring | Code-signing verification (Linux distros) | New key trusted | **uncovered** |
| SSH `known_hosts` | All git operations over SSH | Added host fingerprint | partial via `--ssh-check` (focuses on `authorized_keys`) |
| Sigstore / Rekor trust roots | All sigstore verifications | Forced root rotation outside policy | **uncovered** |
| DNS resolver config | Where package fetches actually go | `/etc/resolv.conf` change, attacker-run resolver | **uncovered** |
| `/etc/hosts` overrides | Same | Registry hostname pointed at attacker IP | **uncovered** |
| `$PATH` / `$PYTHONPATH` / `$NODE_PATH` / `$GOPATH` | Which binaries and modules resolve | Entry prepended in shell rc | partial — shell rc scan |
| `pip.conf` / `.npmrc` / `~/.cargo/config.toml` / `~/.gemrc` | Which registry your tools fetch from | `index-url` or `registry=` flipped | partial — `.npmrc` token-leak scan, no registry-override detection |
| Git config `insteadOf` rewrites | Where `git clone` resolves to | `[url "evil"] insteadOf = github.com` | **uncovered** |
| Lockfile integrity hashes | Whether on-disk matches what was pinned | Hash silently rewritten | partial — chdora gate preflight verifies for npm |
| Package-manager-internal sumdb (Go `sum.golang.org`) | Cross-checks module bytes | Sumdb proxy MITM | **uncovered** |

**Why this matters.** A user can have every gate enabled, every check
green, every package signed — and still be fully compromised if the
attacker flipped `.npmrc registry=https://evil-mirror.example.com/`
silently. **This is forensics territory, not gate territory** — the
check is "did this trust anchor drift from a baseline?", not "is
this install allowed?".

---

## 5. Adjacent surfaces

Related boundaries that share the supply-chain shape (external trust,
code execution) but live partly outside chaindora's core scope.

### Infrastructure-as-code

| Surface | Why supply-chain risk |
|---|---|
| Terraform / OpenTofu modules | `source = "..."` pulls arbitrary modules from git, registry, S3 |
| Terraform / OpenTofu providers | Provider binaries downloaded + executed during plan |
| Helm charts | `dependencies:` pulls third-party charts; chart hooks run cluster-scoped code |
| Ansible Galaxy roles + collections | Run as root on every managed host |
| Pulumi providers | Same shape as Terraform providers |
| ArgoCD / FluxCD app sources | Git URL is the trust unit; what's in the repo runs as cluster operator |
| Crossplane providers | Cluster-scoped provider binaries |
| Chef cookbooks / Berkshelf | Same |
| Puppet modules / r10k | Same |

**All uncovered.** Each fits the existing gate model: identify the
source (registry / git URL / artifact), apply cooldown / OSV /
publisher checks, scan for execution patterns. Per-ecosystem work but
one architecture.

### AI / ML

| Surface | Why supply-chain risk |
|---|---|
| HuggingFace model weights | `.from_pretrained()` loads pickle → arbitrary RCE |
| PyTorch / TF / Keras model files | `torch.load`, `pickle.load` invoke `__reduce__` |
| Custom tokenizers / datasets | Loader code runs at import |
| MLflow / W&B / DVC model registries | Trust-by-URL |
| LangChain / LlamaIndex tools | pip-distributed plugins |
| Agent framework plugins (MCP, Claude Code skills, Cursor extensions, ChatGPT plugins) | Trust the marketplace |

**All uncovered.** HuggingFace pickle scanning is the highest-priority
gap — there's a documented attack-pattern increase 2024–2026, and
the detection ("scan for `__reduce__` opcodes in the pickle stream")
is mechanical.

### Identity / authentication

| Surface | Why supply-chain risk |
|---|---|
| GitHub Apps installed on org | Third-party access to all repos |
| OAuth tokens / scopes for SaaS apps | Compromise propagates to that SaaS |
| GitHub Actions `GITHUB_TOKEN` scope (write-all) | Workflow token can be over-privileged |
| Self-hosted CI runners | Full CI hijack on compromise |
| PyPI trusted publishers (OIDC) | Misconfigured binding |
| npm publish tokens | Account takeover vector |

**Partly out-of-scope.** Identity-platform compromise is a different
tool class (GitGuardian, Datadog Cloud SIEM, GitHub Advanced
Security). chaindora's contribution here is bounded:
- `chdora audit` could grep for `permissions: write-all` in workflow files
- `chdora audit` could enumerate installed GitHub Apps if a token is provided
- We do **not** want to be in the credential-rotation business

### Developer-environment supply chain

| Surface | Coverage |
|---|---|
| Editor configs that pull code (devcontainer features, `tasks.json` auto-run) | partial |
| Shell plugin frameworks (oh-my-zsh, oh-my-fish, prezto) | partial — `hostforensics:shellrc` |
| Vim / Neovim / Emacs plugin managers | **uncovered** |
| JetBrains / Cursor / Helix marketplaces | partial — extensions detector |
| direnv `.envrc` | **uncovered** |
| `mise` / `asdf` / `fnm` / `nvm` version-manager configs | **uncovered** — they download runtimes |
| `gh extension install` / `cargo install` / `pip install --user` global tools | partial — `--deep` enumerates installed |

---

## 6. Scope boundaries

chaindora is **a supply-chain attack tool**, not a general-purpose
security platform. These are deliberately out of scope:

### Out of scope — different tool class

| Domain | Why not chaindora | Better tool class |
|---|---|---|
| Runtime behavior monitoring (process / network / syscall) | Different telemetry model, different deployment | Falco, Tetragon, eBPF tools |
| EDR / XDR / endpoint protection | Different threat model (general malware vs supply chain) | CrowdStrike, SentinelOne |
| SIEM / log aggregation | Different scale, different access pattern | Datadog, Elastic, Splunk |
| Identity / OAuth scope auditing | Different surface (cloud platform APIs) | GitGuardian, Wiz, Datadog CSPM |
| Network DLP | Different intercept point | Netskope, Zscaler |
| Credential rotation / secrets management | Different operational concern | Vault, AWS Secrets Manager, Doppler |
| Vulnerability scanning of compiled binaries (binary analysis) | Different analysis stack | Snyk, Trivy (overlap), Veracode |

### Out of scope — explicit non-features

- **chaindora will never auto-rotate credentials.** Fix plans for token-leak
  findings are `manual` category by design. Auto-rotation is an operational
  concern owned by the credential's actual service.
- **chaindora will never modify shell rc files.** Suspected shell-rc
  tampering is reported, not corrected. The user must triage.
- **chaindora will never disable extensions or kill processes.** Detection
  + remediation plan, not active enforcement at runtime.
- **chaindora will not enroll machines into a fleet without explicit
  opt-in.** Server mode (planned v0.13) is opt-in via config; the
  default chdora binary is single-machine and does not phone home.

### In-scope but follow tool-of-record conventions

- **OS package managers**: detection ✅, gate ❌. Gate would require
  intercepting apt/brew/dnf which is an OS-vendor concern. We report
  what's installed; the user's OS update policy handles gate.
- **Container scanning at registry level**: detection of base-image
  refs ✅, deep image-layer scanning ❌. Trivy / Grype own that.

---

## 7. Prioritization framework

When deciding what to ship next, score each candidate on three axes
and pick the highest-product:

| Axis | Weight | What to measure |
|---|---|---|
| **Empirical attack frequency** | 0–3 | Real attacks observed against this surface in the last 12 months |
| **Blast radius** | 0–3 | What does a successful compromise grant — single project (1), all projects on host (2), org-wide / cluster-wide (3)? |
| **User-base coverage** | 0–3 | How many of our users use this surface? |
| **Effort** | 0.5–3 | Engineering weeks (divisor — lower effort = higher score) |

`score = (frequency × blast_radius × user_base) / effort`

This explicitly says: shipping yet another rare-ecosystem parser is
worse than closing a high-blast-radius gap in npm even if the latter
is more boring.

---

## 8. Re-ranked roadmap

Driven by the framework. Each milestone has a primary threat-model
target rather than an ecosystem target.

### v0.11 — ✅ shipped — close the highest-leverage gaps

Score-ranked items shipped:

1. ✅ **Git-URL trust evaluator** — `pip install git+...`,
   `npm install user/repo`, CMake `FetchContent_Declare`,
   `go get` against unknown hosts. Host-tier + ref-pin +
   transport-scheme scoring. 40-hex SHA on a well-known host =
   Approve; branch refs / unknown hosts / `http://` = Block under
   Strict.
2. ✅ **Build-time + import-time static scan** for Go `init()` and
   Rust `build.rs` / proc-macros. Same scanner architecture as npm
   postinstall.
3. ✅ **Trust-anchor drift forensics** — baseline at first run,
   alert on drift across `.npmrc` / `pip.conf` / `~/.cargo/config.toml` /
   `git config insteadOf` / ssh `known_hosts` / system CA store /
   `/etc/hosts`.
4. ✅ **RubyGems + crates + Maven** detection + cooldown + OSV.
5. ✅ **PyPI gate parity completion** — publisher-change /
   maintainer-trust / version-diff.

### v0.13 — ✅ shipped — server mode + multi-machine

JSON-backed `chdora server` with per-agent bearer tokens, embedded
HTML dashboard at `/`, JSON API at `/api/v1/*`. Bring-your-own TLS.
`chdora agent enroll` + `chdora watch` for client-side pushing.

### v0.13.1 — ✅ shipped — lockfile-vs-registry integrity

`go.sum` cross-referenced against sum.golang.org transparency log;
`Cargo.lock` checksums verified against crates.io index. v0.15
extended this with lockfile-vs-disk drift checks.

### v0.14 — ✅ shipped — ecosystem coverage push (8 → 42 PMs)

The headline release. Gate-side ecosystem coverage expanded from
8 to 42 package managers. New resolvers for: NuGet, Composer,
Poetry, uv, Gradle, sbt, CocoaPods, Swift PM, Pub, Mix/Hex, bun,
deno, conda+mamba+micromamba, brew, Conan, vcpkg, Paket, stack,
cabal, opam, renv, Pkg.jl (Julia), cpanm, luarocks, Elm, nimble,
shards, zig.

Also shipped: hash-keyed verdict cache at `~/.chaindora/gate-cache/`
+ republish-attack detector (same `name@version` reappearing with
different bytes → critical Block). Parallel checker fan-out in
`gate.Run`. `PMError` typed errors so chdora stays silent when the
real package manager would have failed anyway.

### v0.15 — ✅ shipped — predictive detection + fleet behavioral

Predictive detector replays the gate's behavioral checkers
(cooldown, publisher-change, maintainer-trust, version-diff,
provenance, republish-guard) against the scan inventory across
32 ecosystems. Findings default to severity medium (advisory).

Three fleet signals on the v0.13 server: `fleet:republish-detected`
(cross-agent integrity divergence), `fleet:publish-cadence-anomaly`
(4+ versions in 24h), `fleet:cohort-fresh-install` (new agent
reports a long-stable version). All require multi-agent state.

Lockfile-vs-disk drift detection: npm/yarn/pnpm (critical),
cargo/go/pip (medium).

### v0.15.1 — ✅ shipped — `gate install` persists across reboots

The original v0.9 `chdora gate install` printed an `export PATH=…`
line and asked the user to add it to their shell rc by hand. Most
users skipped that step, so the gate was effectively off. v0.15.1
appends a fence-marker block to the user's shell rc directly (zsh /
bash / fish / PowerShell). `chdora gate disable` removes the block
surgically.

### v0.15.2 — ✅ shipped — manifest fallbacks + predictive tuning

Four manifest-fallback parsers for the real-world case where a
project has only the manifest, not the lockfile: `.csproj` /
`.fsproj` / `.vbproj` (NuGet without `<RestorePackagesWithLockFile>`),
`build.gradle` / `build.gradle.kts` (Gradle without
`dependencyLocking`), `composer.json` (libraries committing only
the manifest), `pyproject.toml` (Poetry/uv/PDM projects mid-
development).

Critical bug fix: v0.15.0's lockfile-vs-disk check mis-reported
every non-hoisted nested-dep entry as drift, producing 1100+ false
positives on real-world projects. Now walks the EXACT lockfile
path per entry (npm) or dedupes by name + checks against the SET
of pinned versions (yarn/pnpm).

Predictive severity retuned per checker: `republish-guard`=Critical,
`cooldown`+`version-diff`=Medium, `publisher-change`+
`maintainer-trust`+`provenance`=Low. Default `--fail-on=critical,
high` CI gates see ZERO advisory predictive noise.

Provenance regression-only firing: warn only when the LATEST
published version of the package also lacks attestation AND a past
version had it. Isolates the real "publisher stopped using
sigstore" pattern from the common "your old version predates
adoption" case.

`hostforensics:persistence` vendor allowlist: Microsoft Office /
OneDrive, Google Chrome, Adobe CC, JetBrains, Docker, Apple,
Dropbox, Spotify, Zoom auto-update plists no longer emit
informational findings (the suspicious-command scanner still
runs on them — a vendor plist doing `curl|bash` still trips HIGH).

CLI executive summary surfaces critical+high counts above the
per-section breakdown; predictive section condenses to top-N when
noisy.

### v0.16 — AI / ML supply chain

The next milestone — what v0.14 was originally slated to cover
before the 42-PM coverage push reordered priorities:

1. **HuggingFace pickle scanner** — detect `__reduce__` opcodes in
   model weight files
2. **PyTorch / TF / Keras model file scanner** — same shape
3. **MCP server / Claude Code skill auditor** — emerging surface
4. **Slopsquatting heuristic** — cross-reference LLM-suggested
   package names against typosquat candidates

### v0.17 — IaC supply chain

1. **Terraform / OpenTofu modules** — `source = ` parser, module
   registry cooldown + OSV
2. **Helm charts** — `Chart.yaml` `dependencies:` + chart-hook
   static scan
3. **Ansible Galaxy** — `requirements.yml` parser, Galaxy API
   cooldown

### v0.18 — emerging surfaces

1. **Bun `bun.lockb` binary lockfile parser** — currently
   gate-only; needs `bun pm ls` integration for detection side
2. **Devcontainer feature scanner** (`devcontainer.json` features map)
3. **JetBrains / Vim / Neovim plugin manager inventory**
4. **PlatformIO embedded ecosystems**

### v1.0 — reproducible-build verification

For packages with sigstore provenance, byte-compare the published
tarball against what would build from the attested git commit at
the attested SHA. Closes the "registry compromised but source
clean" gap. Heavy — depends on per-ecosystem reproducible-build
toolchains being mature enough to compare against.

---

## 9. How to use this document

When proposing a new feature or evaluating a contribution:

1. Locate the attack class in the four-dimension space (§ 1–4)
2. Check if it falls inside the scope boundary (§ 6)
3. Score it under the prioritization framework (§ 7)
4. If it doesn't fit any existing milestone (§ 8), either propose
   a new milestone or argue why this jumps an existing one

The framework is deliberately concrete. "We should add support for
X" is not a useful proposal; "X is a code-entry vector with no
registry-level signing, attack frequency 3, blast radius 2, user-
base 2, effort 1.5, score 8 → should land in v0.11" is.

---

## Pointers

- [README.md](../README.md) — user-facing entry point
- [CLAUDE.md](../CLAUDE.md) — contributor on-ramp
- [docs/architecture.md](./architecture.md) — internal package layout
- [docs/incident-pack.md](./incident-pack.md) — how to contribute incidents
- [docs/ci-integration.md](./ci-integration.md) — per-CI recipes
