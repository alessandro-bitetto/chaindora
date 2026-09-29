# Install Chaindora

[Documentation](README.md) · [Supported scope](../README.md#supported-scope)

Chaindora 0.0.3 ships as one executable, `chdora`, for macOS, Linux and Windows.
The package managers you want to wrap must be installed separately.

## Download a release

Choose an archive from [release 0.0.3](https://github.com/alessandro-bitetto/chaindora/releases/tag/v0.0.3)
and download `chaindora_0.0.3_checksums.txt` from the same release.

| Platform | Architecture | Archive |
|---|---|---|
| macOS | Apple silicon | `chaindora_0.0.3_darwin_arm64.tar.gz` |
| macOS | Intel | `chaindora_0.0.3_darwin_x86_64.tar.gz` |
| Linux | ARM64 | `chaindora_0.0.3_linux_arm64.tar.gz` |
| Linux | x86-64 | `chaindora_0.0.3_linux_x86_64.tar.gz` |
| Windows | ARM64 | `chaindora_0.0.3_windows_arm64.zip` |
| Windows | x86-64 | `chaindora_0.0.3_windows_x86_64.zip` |

Archive names use `darwin` for macOS and `x86_64` for Go's `amd64` architecture.
Archives include the executable, license, documentation and incident YAML files.

### macOS and Linux

In the download directory, calculate the archive's SHA-256 and compare it with
the matching filename in the checksum file. For example, on Apple silicon:

```sh
shasum -a 256 chaindora_0.0.3_darwin_arm64.tar.gz
cat chaindora_0.0.3_checksums.txt
```

On Linux, use `sha256sum` in place of `shasum -a 256`. Both values must match
before extracting the archive. Checksums detect a mismatched download; they
are not signed attestations.

Extract the verified archive into a dedicated directory, then place `chdora`
in a directory on your PATH. This example installs for the current user:

```sh
mkdir -p chaindora-release
# Substitute the archive you verified above.
tar -xzf chaindora_0.0.3_darwin_arm64.tar.gz -C chaindora-release
mkdir -p "$HOME/.local/bin"
install -m 755 chaindora-release/chdora "$HOME/.local/bin/chdora"
export PATH="$HOME/.local/bin:$PATH"
chdora --version
```

Add the PATH entry to your shell configuration if it is not already present.
The expected output is `chdora 0.0.3`.

### Windows

In PowerShell, compare the SHA-256 value with the matching checksum-file entry,
then extract the verified ZIP:

```powershell
Get-FileHash .\chaindora_0.0.3_windows_x86_64.zip -Algorithm SHA256
Get-Content .\chaindora_0.0.3_checksums.txt
# Run after the values match; substitute the ARM64 archive when appropriate.
Expand-Archive .\chaindora_0.0.3_windows_x86_64.zip -DestinationPath .\chaindora-release
.\chaindora-release\chdora.exe --version
```

Move the extracted directory to a permanent location and add that directory to
your user PATH. Open a new terminal and check `chdora --version` again.

## Install from source

Use a supported Go toolchain that satisfies the project's Go 1.22 minimum:

```sh
go install github.com/alessandro-bitetto/chaindora/cmd/chdora@v0.0.3
chdora --version
```

Go installs to `GOBIN` when configured, otherwise the first `GOPATH` entry's
`bin` directory. Inspect those values with `go env GOBIN GOPATH` and add the
appropriate directory to PATH. A source installation installs the executable;
it does not copy the curated incident pack.

To build a local checkout:

```sh
go build -o chdora ./cmd/chdora
./chdora --version
```

## Upgrade an existing installation

For a manually installed release binary:

```sh
chdora upgrade --check
chdora upgrade --version v0.0.3
chdora --version
```

The upgrade verifies the release archive's SHA-256 and replaces the executable.
It needs write access to the installation directory. For a source installation,
rerun the version-pinned `go install` command above. If a package manager owns
the executable, update it through that manager.

On macOS/Linux, `/usr/local/bin` is often owned by root. Even if you own the
`chdora` file, atomic replacement needs write permission on its directory. For
a manually installed binary at that location, run:

```sh
sudo /usr/local/bin/chdora upgrade --version v0.0.3
chdora --version
```

Enter your administrator password in the terminal when prompted. Alternatively,
install in a user-writable directory on your PATH.

## Load incident data and run a scan

Fetch the curated incident pack, then scan from your project directory:

```sh
chdora update
chdora scan .
```

`update` fetches incident YAML from this repository into `~/.chaindora/incidents`.
Review its added/updated/skipped counts. It does not upgrade the executable or
refresh OSV advisories; online scans query OSV separately. You can select a pack
explicitly, including the one supplied in the release archive:

```sh
chdora scan . --incidents /path/to/chaindora-release/incidents
```

Use an absolute path to the extracted `incidents` directory on your machine.
In PowerShell, quote Windows paths containing spaces. Explicit selection also
avoids depending on environment-specific home-directory lookup.

For local checks without network-backed detectors:

```sh
chdora scan . --offline --incidents /path/to/chaindora-release/incidents
```

Offline mode reduces coverage. Review [the threat model](threat-model.md) when
interpreting the result.

## Add the install gate

Start with an explicit invocation; gate flags precede the manager name:

```sh
chdora gate exec --dry-run npm install lodash@4.17.21
```

This example demonstrates syntax. It still runs dependency resolution and is
not a sandbox. It prints the gate result without executing the final install.

On macOS/Linux, optionally install the shell wrappers:

```sh
chdora gate install
# Open a new terminal, then:
chdora gate status
```

On Windows, use `chdora gate exec <manager> <arguments>` directly. Automatic
Windows wrapper installation is incomplete: the generated files are not native
`.cmd`/PowerShell wrappers that can be relied on for interception.

See [command coverage and policy](../README.md#prevention) before enabling the
gate. Bare installs and several restore/build paths can pass through ungated.
To remove managed shell integration on macOS/Linux, run `chdora gate disable`
and open a fresh terminal.
