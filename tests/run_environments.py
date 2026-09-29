#!/usr/bin/env python3
"""Run real-manager and CLI contracts in disposable, network-disabled Linux containers.

--prepare downloads official toolchains and builds tool-only images first.
Test runs cannot pull images or access external networking. Fixtures are locally
generated; no malicious packages are installed or executed. Requires Go, Python
3.9+, and Docker. A nonzero result means at least one contract failed.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGES = {
    "node": "chaindora-test-node:local",
    "python": "chaindora-test-python:local",
    "paket": "chaindora-test-paket:local",
    "bun": "oven/bun@sha256:9114c058aeae42162ee16dd5084b95fe9473970bb6bcb5b232ab1630f0546895",
    "deno": "denoland/deno@sha256:fa335acdf6b72106eda2cb6a8cb5f4187e7630e357467489db4b2e7352d5e432",
    "cargo": "rust@sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7",
    "go": "golang@sha256:6c2a5538f964f1c82f97ad14988bf05de100d922d159d0e398b54c7b0ca0c6c9",
    "dotnet": "mcr.microsoft.com/dotnet/sdk@sha256:fc69dc5e0c9789adaac5c8efce71ead4d016a51318667c4f26ce93574b1b9403",
}
GROUPS = {
    "node": ("node", "npm,yarn,pnpm", []),
    "yarn-berry": ("node", "yarn", ["-e", "CHAINDORA_TEST_BIN_YARN=/opt/yarn-berry/node_modules/.bin/yarn"]),
    "python": ("python", "pip,pip3,poetry,uv,pipenv,pdm", []),
    "bun": ("bun", "bun", []), "deno": ("deno", "deno", []),
    "cargo": ("cargo", "cargo", []), "go": ("go", "go", []),
    "dotnet": ("dotnet", "dotnet", []), "paket": ("paket", "paket", []),
    "cli": ("python", "", []),
}


def checked(arguments, **kwargs):
    return subprocess.run(arguments, check=True, cwd=ROOT, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--only", choices=GROUPS, nargs="+")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    groups = args.only or list(GROUPS)
    if args.prepare:
        with (output / "toolchain-setup.log").open("w") as log:
            for group in ("bun", "deno", "cargo", "go", "dotnet"):
                if group in groups:
                    checked(["docker", "pull", IMAGES[group]], stdout=log, stderr=subprocess.STDOUT)
            for group, filename in (("node", "Node"), ("python", "Python"), ("paket", "Paket")):
                if any(GROUPS[name][0] == group for name in groups):
                    checked(["docker", "build", "-f", str(ROOT / "tests/environments" / (filename+".Dockerfile")),
                             "-t", IMAGES[group], str(ROOT / "tests/environments")], stdout=log, stderr=subprocess.STDOUT)

    arch = checked(["docker", "info", "--format", "{{.Architecture}}"], capture_output=True, text=True).stdout.strip()
    arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(arch, arch)
    if arch not in ("arm64", "amd64"):
        raise SystemExit("Unsupported Docker architecture: "+arch)
    image_ids = {}
    for name in groups:
        image = IMAGES[GROUPS[name][0]]
        image_ids[image] = checked(["docker", "image", "inspect", image, "--format", "{{.Id}}"], capture_output=True, text=True).stdout.strip()
    (output / "images.json").write_text(json.dumps(image_ids, indent=2)+"\n")
    results = []
    with tempfile.TemporaryDirectory(prefix="chaindora-test-binaries-") as temp:
        binary = Path(temp) / "gate.test"
        cli = Path(temp) / "chdora"
        env = dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0")
        checked(["go", "test", "-c", "-o", str(binary), "./internal/gate"], env=env)
        checked(["go", "build", "-o", str(cli), "./cmd/chdora"], env=env)
        for name in groups:
            image_name, managers, extra = GROUPS[name]
            container = "chaindora-validation-"+uuid.uuid4().hex
            command = ["docker", "run", "--name", container, "--rm", "--pull=never", "--network=none",
                       "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                       "--user=65532:65532", "--tmpfs=/tmp:rw,exec,size=2g", "-e", "HOME=/tmp"]
            if name == "cli":
                command += ["--mount", f"type=bind,src={cli},dst=/chdora,readonly",
                            "--mount", f"type=bind,src={ROOT / 'tests/offline_cli.py'},dst=/offline_cli.py,readonly",
                            "--entrypoint=python", IMAGES[image_name], "/offline_cli.py",
                            "--binary=/chdora", "--output=/tmp/results"]
            else:
                command += ["-e", "CHAINDORA_REAL_PM_TESTS=1", "-e", "CHAINDORA_TEST_MANAGERS="+managers]
                if image_name in ("node", "bun", "deno"):
                    command += ["-e", "CHAINDORA_TEST_LIFECYCLE=1"]
                command += extra + ["--mount", f"type=bind,src={binary},dst=/gate.test,readonly",
                                    "--entrypoint=/gate.test", IMAGES[image_name],
                                    "-test.run=^TestReal", "-test.v", "-test.timeout=3m"]
            try:
                with (output / (name+".log")).open("w") as log:
                    result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=210)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 124
            finally:
                subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            results.append({"group": name, "exit_code": code, "log": name+".log"})
            print(f"{'PASS' if code == 0 else 'FAIL'} {name}: exit {code}", flush=True)
    (output / "results.json").write_text(json.dumps(results, indent=2)+"\n")
    return int(any(item["exit_code"] != 0 for item in results))


if __name__ == "__main__":
    raise SystemExit(main())
