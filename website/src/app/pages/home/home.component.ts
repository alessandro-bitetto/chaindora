import { Component } from '@angular/core';

interface Milestone {
  tag: string;
  state: 'shipped' | 'current' | 'planned';
  what: string;
}

@Component({
  selector: 'cd-home',
  standalone: true,
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.scss'],
})
export class HomeComponent {
  readonly version = '0.15.2';

  readonly roadmap: Milestone[] = [
    { tag: 'v0.10', state: 'shipped', what: 'SonarQube-grade ci (baseline / suppression / PR comments); yarn + pnpm gate resolvers; PyPI gate; watch daemon; sigstore' },
    { tag: 'v0.11', state: 'shipped', what: 'Pluggable gate; RubyGems + crates + Maven full stacks; build-time scan; trust-anchor drift; git-URL evaluator' },
    { tag: 'v0.13', state: 'shipped', what: 'Server mode + agent enrollment + fleet dashboard; go.sum integrity; complete provenance / publisher matrix' },
    { tag: 'v0.14', state: 'shipped', what: 'Coverage push to 42 package managers across 20+ languages — .NET, Composer, Poetry, uv, Gradle, sbt, CocoaPods, Swift PM, Pub, Mix/Hex, bun, deno, conda, brew, Conan, vcpkg, Paket, stack, cabal, opam, renv, Pkg.jl, cpanm, luarocks, Elm, nimble, shards, zig. Hash-keyed verdict cache + republish-attack detector.' },
    { tag: 'v0.15', state: 'shipped', what: 'Predictive detection across 32 ecosystems (full parity with the v0.14 gate-side push) — cooldown, publisher-change, maintainer-trust, version-diff, republish-guard replayed against installed packages. Lockfile-vs-disk integrity drift for npm/yarn/pnpm/cargo/go/pip. Three fleet signals: cross-agent republish-detection, publish-cadence anomaly (4+ versions in 24h), cohort fresh-install.' },
    { tag: 'v0.16', state: 'planned', what: 'AI/ML supply chain — HuggingFace pickle, PyTorch/TF model files, MCP / agent-framework auditor' },
    { tag: 'v0.17', state: 'planned', what: 'IaC supply chain — Terraform / OpenTofu / Helm / Ansible Galaxy' },
    { tag: 'v0.18', state: 'planned', what: 'Emerging surfaces — devcontainer features + slopsquatting + plugin-manager inventory + PlatformIO' },
    { tag: 'v1.0', state: 'planned', what: 'Reproducible-build verification: byte-compare published tarball against attested git source' },
  ];
}
