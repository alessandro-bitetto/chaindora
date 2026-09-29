import { CommonModule } from '@angular/common';
import { Component, OnDestroy } from '@angular/core';
import { RouterLink } from '@angular/router';

type Ecosystem = {
  name: string;
  registry: string;
  managers: string;
  command: string;
  inventory: string;
  note: string;
};

@Component({
  selector: 'cd-home',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './home.component.html',
  styleUrl: './home.component.scss',
})
export class HomeComponent implements OnDestroy {
  readonly github = 'https://github.com/alessandro-bitetto/chaindora';
  readonly sourceInstall = 'go install github.com/alessandro-bitetto/chaindora/cmd/chdora@v0.0.1';
  readonly ecosystems: Ecosystem[] = [
    { name: 'npm', registry: 'JavaScript & TypeScript', managers: 'npm · Yarn · pnpm · Bun · Deno', command: 'chdora gate exec npm install lodash@4.17.21', inventory: 'package-lock.json · yarn.lock · pnpm-lock.yaml · deno.lock', note: 'Registry signals and package-source patterns. Bun has an install resolver but no lockfile inventory parser. Deno coverage is limited to npm dependencies.' },
    { name: 'PyPI', registry: 'Python', managers: 'pip · pip3 · Poetry · uv · Pipenv · PDM', command: 'chdora gate exec pip install requests==2.32.3', inventory: 'requirements.txt · poetry.lock · uv.lock · Pipfile.lock · pdm.lock · pyproject.toml', note: 'Inspect registry artifacts and Python credential-collection patterns. Source builds during resolution still need isolation; the gate is not a sandbox.' },
    { name: '.NET', registry: 'NuGet', managers: 'dotnet · Paket', command: 'chdora gate exec dotnet add package Newtonsoft.Json --version 13.0.3', inventory: 'packages.lock.json · paket.lock · .csproj · .fsproj · .vbproj', note: 'NuGet inventory, known advisories, publish history and package metadata. Manifest fallbacks are less precise than resolved lockfiles; .NET bytecode is not analyzed.' },
    { name: 'Go', registry: 'Go modules', managers: 'Go tooling', command: 'chdora gate exec go get golang.org/x/text@v0.28.0', inventory: 'go.mod · go.sum', note: 'Module inventory, checksum evidence and suspicious Go init() patterns. Support follows modules through the existing Go resolver.' },
    { name: 'Rust', registry: 'crates.io', managers: 'Cargo', command: 'chdora gate exec cargo add serde@1.0.219', inventory: 'Cargo.lock', note: 'Crate inventory, checksum evidence and build.rs source patterns. Build-script inspection is heuristic; builds are not isolated by the gate.' },
  ];
  selected = 0;
  mode: 'prevent' | 'detect' = 'prevent';
  copied = '';
  copyError = '';
  private copyTimer?: ReturnType<typeof setTimeout>;

  ngOnDestroy(): void {
    if (this.copyTimer) clearTimeout(this.copyTimer);
  }

  get ecosystem(): Ecosystem { return this.ecosystems[this.selected]; }

  selectEcosystem(index: number): void {
    this.selected = index;
    this.copied = '';
    this.copyError = '';
  }

  onTabKey(event: KeyboardEvent, index: number): void {
    let next = index;
    if (event.key === 'ArrowRight') next = (index + 1) % this.ecosystems.length;
    else if (event.key === 'ArrowLeft') next = (index + this.ecosystems.length - 1) % this.ecosystems.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = this.ecosystems.length - 1;
    else return;
    event.preventDefault();
    this.selectEcosystem(next);
    document.getElementById('ecosystem-tab-' + next)?.focus();
  }

  async copy(value: string, id: string): Promise<void> {
    this.copyError = '';
    try {
      await navigator.clipboard.writeText(value);
      this.copied = id;
      if (this.copyTimer) clearTimeout(this.copyTimer);
      this.copyTimer = setTimeout(() => this.copied = '', 2200);
    } catch {
      this.copyError = 'Clipboard unavailable. Select the command to copy it manually.';
    }
  }
}
