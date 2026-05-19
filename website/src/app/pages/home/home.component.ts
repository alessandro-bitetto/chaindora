import { Component } from '@angular/core';

interface RoadmapItem {
  title: string;
  desc: string;
}

interface RoadmapPhase {
  // 'now' is the active phase; 'next' is the committed next step;
  // 'later' is everything beyond that, intentionally less concrete.
  state: 'now' | 'next' | 'later';
  label: string;
  headline: string;
  items: RoadmapItem[];
}

@Component({
  selector: 'cd-home',
  standalone: true,
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.scss'],
})
export class HomeComponent {
  readonly version = '0.16.0';

  // Roadmap is goal-driven, not version-driven. Specific tags will
  // attach to these phases as they ship; what matters for a reader
  // is "what's the next problem this project is trying to solve",
  // not "v0.17 vs v0.18".
  readonly roadmap: RoadmapPhase[] = [
    {
      state: 'now',
      label: 'Now',
      headline: 'Stabilize what already ships.',
      items: [
        {
          title: 'Structured test suite',
          desc: 'Per-ecosystem integration suite — the prerequisite for awarding the `stable` badge. Today the suite exists informally; the next step is making it a release gate.',
        },
        {
          title: 'Field-test the 38 untested ecosystems',
          desc: 'chaindora ships code for 42 package managers but only 4 (npm, PyPI, Go, .NET) have been exercised in production. Real-world feedback on the rest is the only way to find the gaps.',
        },
        {
          title: 'Promote ecosystems to `stable`',
          desc: 'As ecosystems pass the suite + accumulate production usage, they earn the `stable` badge on the coverage grid above. Goal: at least 8 stable by end of phase.',
        },
      ],
    },
    {
      state: 'next',
      label: 'Next',
      headline: 'AI / ML supply chain.',
      items: [
        {
          title: 'Model artifact scanner',
          desc: 'HuggingFace pickle (`__reduce__` opcodes), PyTorch / TF / Keras serialized weights — static scan for executable payloads and tampered checkpoints.',
        },
        {
          title: 'MCP / agent-framework auditor',
          desc: 'Inventory the LLM-agent tool surface — which MCP servers are exposed, what permissions, what trust assumptions.',
        },
        {
          title: 'Slopsquatting heuristic',
          desc: 'Cross-reference LLM-suggested package names against typosquat candidates to flag hallucinated dependencies before install.',
        },
      ],
    },
    {
      state: 'later',
      label: 'After',
      headline: 'Adjacent supply chains.',
      items: [
        {
          title: 'IaC supply chain',
          desc: 'Terraform / OpenTofu module registries, Helm charts, Ansible Galaxy — same gate + detection model on the infra side.',
        },
        {
          title: 'Emerging surfaces',
          desc: 'Devcontainer features, plugin-manager inventory, PlatformIO, browser/IDE marketplace deltas.',
        },
        {
          title: 'Reproducible-build verification (v1.0)',
          desc: 'Byte-compare published tarball against attested git source. Closes the loop on "trust the maintainer, verify the bytes".',
        },
      ],
    },
  ];
}
