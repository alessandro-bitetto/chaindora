import { Component, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';

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
export class HomeComponent implements OnInit {
  // Fallback shown before the API responds (and if the request fails).
  // Replaced at runtime with the real latest release so the page never
  // shows a stale version after a release is cut.
  version = '0.16.0';

  // Install snippets live in the component (not inline in the template) so
  // their shell ${...} / %{...} braces aren't parsed by Angular's control-flow
  // template compiler. Both resolve the latest release at run time — never a
  // pinned version — and cover macOS/Linux + Windows.
  readonly unixInstall =
    "OS=$(uname -s | tr '[:upper:]' '[:lower:]')\n" +
    'ARCH=$(uname -m); case "$ARCH" in x86_64|amd64) ARCH=x86_64 ;; arm64|aarch64) ARCH=arm64 ;; esac\n' +
    "TAG=$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/alessandro-bitetto/chaindora/releases/latest | sed 's#.*/##')\n" +
    'curl -fL "https://github.com/alessandro-bitetto/chaindora/releases/download/$TAG/chaindora_${TAG#v}_${OS}_${ARCH}.tar.gz" | tar xz\n' +
    'sudo mv chdora /usr/local/bin/';

  readonly windowsInstall =
    '$tag = (Invoke-RestMethod https://api.github.com/repos/alessandro-bitetto/chaindora/releases/latest).tag_name\n' +
    "$ver = $tag.TrimStart('v')\n" +
    'Invoke-WebRequest "https://github.com/alessandro-bitetto/chaindora/releases/download/$tag/chaindora_${ver}_windows_x86_64.zip" -OutFile chdora.zip\n' +
    'Expand-Archive chdora.zip -DestinationPath $HOME\\.chaindora\\bin -Force\n' +
    '# add chdora to your PATH (User scope) — open a new terminal afterwards\n' +
    '$bin = "$HOME\\.chaindora\\bin"\n' +
    "$old = [Environment]::GetEnvironmentVariable('Path','User')\n" +
    'if ($old -notlike "*$bin*") { [Environment]::SetEnvironmentVariable(\'Path\', "$old;$bin", \'User\') }';

  constructor(private readonly http: HttpClient) {}

  // Copy an install snippet to the clipboard and flash "Copied" on the button.
  copy(text: string, ev: Event): void {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(text);
    }
    const btn = ev.currentTarget as HTMLButtonElement | null;
    if (!btn) {
      return;
    }
    btn.textContent = 'Copied';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = 'Copy';
      btn.classList.remove('copied');
    }, 1500);
  }

  ngOnInit(): void {
    this.http
      .get<{ tag_name?: string }>(
        'https://api.github.com/repos/alessandro-bitetto/chaindora/releases/latest',
      )
      .subscribe({
        next: (release) => {
          const tag = release?.tag_name?.trim();
          if (tag) {
            this.version = tag.replace(/^v/, '');
          }
        },
        error: () => {
          /* keep the fallback version */
        },
      });
  }

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
