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
  readonly version = '0.13.2';

  readonly roadmap: Milestone[] = [
    { tag: 'v0.10', state: 'shipped', what: 'SonarQube-grade ci (baseline / suppression / PR comments); yarn + pnpm gate resolvers; PyPI gate; watch daemon; sigstore' },
    { tag: 'v0.11', state: 'shipped', what: 'Pluggable gate; RubyGems + crates + Maven full stacks; build-time scan; trust-anchor drift; git-URL evaluator' },
    { tag: 'v0.13', state: 'shipped', what: 'Server mode + agent enrollment + fleet dashboard; go.sum integrity; complete provenance / publisher matrix' },
    { tag: 'v0.14', state: 'planned', what: 'IaC supply chain — Terraform / Helm / Ansible / Composer / NuGet' },
    { tag: 'v0.15', state: 'planned', what: 'AI/ML supply chain — HuggingFace pickle, PyTorch/TF model files, MCP / agent-framework auditor' },
    { tag: 'v0.16', state: 'planned', what: 'Bun + Deno + devcontainer features + slopsquatting + plugin-manager inventory' },
    { tag: 'v1.0', state: 'planned', what: 'Reproducible-build verification: byte-compare published tarball against attested git source' },
  ];
}
