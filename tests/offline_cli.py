#!/usr/bin/env python3
"""Black-box CLI contracts with inert manifests and synthetic incident data.

No package manager installs any package. The POSIX manager doubles only return
an error or write a marker file. Run with --network none for enforced isolation.
Failures are genuine failed contracts, not expected-failure passes.
"""

import argparse
import base64
import hashlib
import io
import tarfile
import json
import os
from pathlib import Path
import subprocess
import tempfile


LEAF = "chaindora-fixture-leaf"
INCIDENT = "TEST-CHAINDORA-HARMLESS-FIXTURE"


def manifests():
    toml = f'[[package]]\nname = "{LEAF}"\nversion = "1.0.0"\n'
    return {
        "npm-v3": {"package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "fixture", "version": "0.0.0"},
            "node_modules/" + LEAF: {"version": "1.0.0", "integrity": "sha512-fixture"}}})},
        "yarn-classic": {"yarn.lock": f'# yarn lockfile v1\n\n{LEAF}@^1.0.0:\n  version "1.0.0"\n  integrity sha512-fixture\n'},
        "yarn-berry": {"yarn.lock": f'__metadata:\n  version: 8\n\n"{LEAF}@npm:^1.0.0":\n  version: 1.0.0\n  resolution: "{LEAF}@npm:1.0.0"\n  checksum: fixture\n'},
        "pnpm-v9": {"pnpm-lock.yaml": f"lockfileVersion: '9.0'\npackages:\n  {LEAF}@1.0.0:\n    resolution: {{integrity: sha512-fixture}}\n"},
        "deno-v3": {"deno.lock": json.dumps({"version": "3", "npm": {"packages": {LEAF+"@1.0.0": {"integrity": "sha512-fixture"}}}})},
        "deno-v5": {"deno.lock": json.dumps({"version": "5", "specifiers": {"npm:"+LEAF+"@1.0.0": "1.0.0"}, "npm": {LEAF+"@1.0.0": {"integrity": "sha512-fixture"}}})},
        "pip-requirements": {"requirements.txt": LEAF+"==1.0.0\n"},
        "poetry": {"poetry.lock": toml},
        "uv": {"uv.lock": 'version = 1\n'+toml},
        "pdm": {"pdm.lock": toml},
        "pipenv": {"Pipfile.lock": json.dumps({"_meta": {}, "default": {LEAF: {"version": "==1.0.0", "hashes": ["sha256:fixture"]}}, "develop": {}})},
        "nuget": {"packages.lock.json": json.dumps({"version": 1, "dependencies": {"net8.0": {"Chaindora.Fixture.Leaf": {"type": "Transitive", "resolved": "1.0.0", "contentHash": "fixture"}}}})},
        "paket": {"paket.lock": "NUGET\n  remote: https://example.invalid/nuget\n    Chaindora.Fixture.Leaf (1.0.0)\n"},
        "go": {"go.mod": "module example.invalid/fixture\n\ngo 1.22\nrequire example.invalid/"+LEAF+" v1.0.0\n", "go.sum": "example.invalid/"+LEAF+" v1.0.0 h1:fixture\n"},
        "cargo": {"Cargo.lock": 'version = 4\n'+toml+'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "fixture"\n'},
        "pyproject-fallback": {"pyproject.toml": '[project]\nname = "fixture"\nversion = "0.0.0"\ndependencies = ["'+LEAF+'==1.0.0"]\n'},
        "csproj-fallback": {"fixture.csproj": '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Chaindora.Fixture.Leaf" Version="1.0.0" /></ItemGroup></Project>'},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    results = []

    def record(name, passed, detail, completed=None):
        results.append({"name": name, "passed": passed, "detail": detail})
        if completed:
            (output / (name+".stdout")).write_text(completed.stdout)
            (output / (name+".stderr")).write_text(completed.stderr)
        print(("PASS " if passed else "FAIL ")+name+": "+detail, flush=True)

    with tempfile.TemporaryDirectory(prefix="chaindora-safe-cli-") as temporary:
        work = Path(temporary)
        home = work / "home"
        home.mkdir()
        env = dict(os.environ, HOME=str(home), USERPROFILE=str(home),
                   XDG_CONFIG_HOME=str(home / "config"), XDG_CACHE_HOME=str(home / "cache"))
        incident_dir = work / "incident-data"
        incident_dir.mkdir()
        # JSON is valid YAML. This is synthetic test intelligence only, never
        # added to the real incident pack and never submitted to a registry.
        packages = [
            {"ecosystem": eco, "name": name, "versions": [version]}
            for eco, name, version in [
                ("npm", LEAF, "1.0.0"), ("PyPI", LEAF, "1.0.0"),
                ("NuGet", "Chaindora.Fixture.Leaf", "1.0.0"),
                ("Go", "example.invalid/"+LEAF, "v1.0.0"),
                ("crates.io", LEAF, "1.0.0")]]
        (incident_dir / "fixture.yaml").write_text(json.dumps({
            "schema": 1, "id": INCIDENT, "name": "Harmless test policy match",
            "severity": "high", "packages": packages,
            "references": ["https://example.invalid/chaindora-test-only"]}))

        def run(cwd, *arguments):
            return subprocess.run([binary, *arguments], cwd=cwd, env=env,
                                  capture_output=True, text=True, timeout=30)

        def scan(cwd, name, *extra):
            sarif = output / (name+".sarif")
            completed = run(cwd, "ci", str(cwd), "--offline", "--skip-heuristic",
                            "--skip-predictive", "--incidents", str(incident_dir),
                            "--format=json", "--sarif", str(sarif), *extra)
            data = json.loads(completed.stdout)
            # JSON output is an array of findings.
            findings = data or []
            sarif_data = json.loads(sarif.read_text())
            sarif_results = sarif_data["runs"][0].get("results", []) or []
            return completed, findings, sarif_results

        for name, files in manifests().items():
            project = work / name
            project.mkdir()
            for filename, content in files.items():
                (project / filename).write_text(content)
            try:
                completed, findings, sarif_results = scan(project, name)
                matches = [f for f in findings if f.get("vuln_id") == INCIDENT]
                passed = completed.returncode == 1 and len(matches) == 1 and len(sarif_results) == 1
                record(name, passed, f"exit={completed.returncode}, synthetic findings={len(matches)}, SARIF results={len(sarif_results)}", completed)
            except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
                record(name, False, str(error))

        policy_project = work / "npm-v3"
        for value in ["critcal", "critical,", "none,high", ""]:
            completed = run(policy_project, "ci", str(policy_project), "--fail-on="+value)
            record("invalid-threshold-"+(value.replace(",", "_") or "empty"),
                   completed.returncode == 2 and "invalid --fail-on" in completed.stderr,
                   f"invalid threshold rejected before scanning; exit={completed.returncode}", completed)

        suppression_path = policy_project / ".chaindora-ignore.yml"
        suppression_path.write_text(json.dumps({"suppress": [{"vuln_id": INCIDENT, "reason": "expired fixture", "expires": "2000-01-01"}]}))
        completed, findings, _ = scan(policy_project, "expired-suppression")
        record("expired-suppression", completed.returncode == 1 and any(f.get("vuln_id") == INCIDENT for f in findings),
               f"expired exception does not hide a finding; exit={completed.returncode}", completed)
        suppression_path.write_text(json.dumps({"suppress": [{"vuln_id": INCIDENT, "reason": "invalid fixture", "expires": "not-a-date"}]}))
        completed = run(policy_project, "ci", str(policy_project), "--offline", "--skip-heuristic", "--incidents", str(incident_dir))
        record("invalid-suppression-date", completed.returncode == 2 and "expires must" in completed.stderr,
               f"invalid expiry rejected; exit={completed.returncode}", completed)
        suppression_path.unlink()

        damaged_pack = work / "damaged-pack"
        damaged_pack.mkdir()
        (damaged_pack / "broken.yaml").write_text("id: [")
        incomplete_baseline = work / "incident-baseline.json"
        incomplete_baseline.write_text(json.dumps({"chdora_version": "fixture", "fingerprints": []}))
        before = incomplete_baseline.read_bytes()
        suppression_path.write_text(json.dumps({"suppress": [{"vuln_id": "CHDORA-INCIDENTS-INCOMPLETE", "reason": "attempted coverage bypass"}]}))
        for label, pack in [("broken-incident-pack", damaged_pack), ("missing-explicit-incident-pack", work / "missing-pack")]:
            completed, findings, sarif_results = scan(policy_project, label, "--incidents", str(pack), "--fail-on=none",
                                                     "--baseline", str(incomplete_baseline), "--update-baseline")
            record(label, completed.returncode == 2 and any(f.get("vuln_id") == "CHDORA-INCIDENTS-INCOMPLETE" for f in findings)
                   and bool(sarif_results) and incomplete_baseline.read_bytes() == before,
                   f"failed pack remains visible and preserves baseline; exit={completed.returncode}", completed)
        suppression_path.unlink()

        alias = work / "npm-alias"
        alias.mkdir()
        (alias / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/harmless-alias": {"name": LEAF, "version": "1.0.0"}}}))
        completed, findings, sarif_results = scan(alias, "npm-alias")
        record("npm-alias", completed.returncode == 1 and len(findings) == 1 and findings[0].get("name") == LEAF,
               f"canonical identity retained; exit={completed.returncode}, findings={len(findings)}", completed)

        # Every byte is inert. The cached archive is authenticated by the fixture
        # lockfile, so this exercises the real CLI without a registry request.
        content_project = work / "installed-content"
        installed = content_project / "node_modules" / "content-fixture"
        installed.mkdir(parents=True)
        files = {"package.json": '{"name":"content-fixture","version":"1.0.0"}', "index.js": "module.exports=1;"}
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, content in files.items():
                payload = content.encode()
                entry = tarfile.TarInfo("package/"+name)
                entry.size = len(payload)
                archive.addfile(entry, io.BytesIO(payload))
                (installed / name).write_bytes(payload)
        data = buffer.getvalue()
        integrity = "sha512-"+base64.b64encode(hashlib.sha512(data).digest()).decode()
        cached = home / ".chaindora" / "artifacts" / (hashlib.sha256(integrity.encode()).hexdigest()+".tgz")
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(data)
        (content_project / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/content-fixture": {"version": "1.0.0", "integrity": integrity,
            "resolved": "https://registry.npmjs.org/content-fixture/-/content-fixture-1.0.0.tgz"}}}))
        completed, findings, _ = scan(content_project, "verified-clean-files")
        record("verified-clean-files", completed.returncode == 0 and not findings,
               f"authenticated clean files; exit={completed.returncode}", completed)
        (installed / "index.js").write_text("module.exports=2;")
        completed, findings, sarif_results = scan(content_project, "modified-installed-source")
        record("modified-installed-source", completed.returncode == 1 and any(f.get("vuln_id") == "INTEGRITY-FILE-MISMATCH" and f.get("source_path", "").endswith("index.js") for f in findings),
               f"source mutation detected; exit={completed.returncode}, findings={len(findings)}", completed)
        cached.unlink()
        completed, findings, _ = scan(content_project, "missing-integrity-evidence", "--fail-on=none")
        record("missing-integrity-evidence", completed.returncode == 2 and any(f.get("vuln_id") == "CHDORA-INTEGRITY-INCOMPLETE" for f in findings),
               f"incomplete inspection cannot pass severity override; exit={completed.returncode}", completed)
        (content_project / ".chaindora-ignore.yml").write_text(json.dumps({"suppress": [{"vuln_id": "CHDORA-INTEGRITY-INCOMPLETE", "reason": "fixture"}]}))
        completed, findings, _ = scan(content_project, "unsuppressible-integrity-failure", "--fail-on=none")
        record("unsuppressible-integrity-failure", completed.returncode == 2 and any(f.get("vuln_id") == "CHDORA-INTEGRITY-INCOMPLETE" for f in findings),
               f"coverage failure remains visible; exit={completed.returncode}", completed)

        clean = work / "clean"
        clean.mkdir()
        (clean / "requirements.txt").write_text(LEAF+"==2.0.0\n")
        completed, findings, sarif_results = scan(clean, "clean-version")
        record("clean-version", completed.returncode == 0 and not findings and not sarif_results,
               f"exit={completed.returncode}, findings={len(findings)}", completed)

        # Manifest fallbacks retain constraints such as ==1.0.0. Check the
        # documented name-level matching separately from exact-version matching.
        incident_file = incident_dir / "fixture.yaml"
        original_incident = incident_file.read_text()
        wildcard = json.loads(original_incident)
        for package in wildcard["packages"]:
            if package["ecosystem"] == "PyPI":
                package["versions"] = ["*"]
        incident_file.write_text(json.dumps(wildcard))
        completed, findings, sarif_results = scan(work / "pyproject-fallback", "pyproject-name-match")
        record("pyproject-name-match", completed.returncode == 1 and len(findings) == 1 and len(sarif_results) == 1,
               f"name-level incident matching: exit={completed.returncode}, findings={len(findings)}", completed)
        incident_file.write_text(original_incident)

        malformed = work / "malformed"
        malformed.mkdir()
        (malformed / "package-lock.json").write_text('{"packages":')
        completed, findings, sarif_results = scan(malformed, "malformed-lock", "--verbose")
        incomplete = [f for f in findings if f.get("vuln_id") == "CHDORA-INVENTORY-INCOMPLETE"]
        record("malformed-lock", completed.returncode == 2 and len(incomplete) == 1 and len(sarif_results) == 1,
               f"a failed inventory must not look clean; exit={completed.returncode}", completed)

        baseline = work / "accepted-baseline.json"
        baseline.write_text(json.dumps({"chdora_version": "fixture", "fingerprints": []}))
        original_baseline = baseline.read_bytes()
        completed, findings, _ = scan(malformed, "malformed-policy-overrides", "--fail-on=none",
                                      "--baseline", str(baseline), "--update-baseline")
        record("malformed-policy-overrides", completed.returncode == 2 and len(findings) == 1 and baseline.read_bytes() == original_baseline,
               f"severity override cannot accept incomplete inventory; exit={completed.returncode}, baseline unchanged={baseline.read_bytes() == original_baseline}", completed)

        (malformed / ".chaindora-ignore.yml").write_text(json.dumps({"suppress": [{
            "vuln_id": "CHDORA-INVENTORY-INCOMPLETE", "reason": "fixture attempts to hide parsing failure"}]}))
        completed, findings, sarif_results = scan(malformed, "malformed-suppression", "--fail-on=none")
        record("malformed-suppression", completed.returncode == 2 and len(findings) == 1 and len(sarif_results) == 1,
               f"coverage failure stays visible despite suppression; exit={completed.returncode}", completed)

        # These are subprocess-control tests using manager DOUBLES, not claims
        # of real package-manager integration. Nothing is downloaded/installed.
        if os.name != "nt":
            bin_dir = work / "manager-doubles"
            bin_dir.mkdir()
            env["PATH"] = str(bin_dir)+os.pathsep+env.get("PATH", "")
            marker = work / "handoff-marker"
            env["CHAINDORA_HANDOFF_MARKER"] = str(marker)
            script = ('#!/bin/sh\nfor argument in "$@"; do\n'
                      ' if [ "$argument" = --node-modules-dir=none ]; then exit 42; fi\ndone\n'
                      'if [ "$1" = cache ]; then\n'
                      ' echo "intentional fixture resolver failure" >&2\n exit 42\nfi\n'
                      'printf "harmless manager handoff" > "$CHAINDORA_HANDOFF_MARKER"\n')
            for manager in ("npm", "deno", "paket"):
                target = bin_dir / manager
                target.write_text(script)
                target.chmod(0o700)
            empty = work / "empty-resolution"
            empty.mkdir()
            (empty / "deno.lock").write_text(manifests()["deno-v5"]["deno.lock"])
            (empty / "paket.lock").write_text("invalid lock fixture\n")
            for manager, arguments in [("deno", ["install"]), ("paket", ["install"])]:
                marker.unlink(missing_ok=True)
                completed = run(empty, "gate", "exec", manager, *arguments)
                record(manager+"-empty-resolution", completed.returncode != 0 and not marker.exists(),
                       f"exit={completed.returncode}, manager handoff={marker.exists()}", completed)
                marker.unlink(missing_ok=True)
                completed = run(empty, "gate", "exec", "--lenient", "--allow-offline", manager, *arguments)
                record(manager+"-empty-relaxed", completed.returncode != 0 and not marker.exists(),
                       f"relaxed policy cannot authorize missing evidence; exit={completed.returncode}, handoff={marker.exists()}", completed)
            for manager, arguments in [("npm", ["install", "fixture"]), ("npm", ["--prefix=/tmp", "install"]), ("deno", ["run", "file.ts"]), ("paket", ["restore"])]:
                marker.unlink(missing_ok=True)
                completed = run(empty, "gate", "exec", manager, *arguments)
                record("refused-"+manager+"-"+arguments[0].replace("/", "_"), completed.returncode != 0 and not marker.exists(),
                       f"unsupported commands never execute; exit={completed.returncode}, handoff={marker.exists()}", completed)
            marker.unlink(missing_ok=True)
            completed = run(empty, "gate", "exec", "--dry-run", "npm", "ci")
            record("passthrough-dry-run", not marker.exists(),
                   f"exit={completed.returncode}, manager handoff={marker.exists()}", completed)
            marker.unlink(missing_ok=True)
            completed = run(empty, "gate", "exec", "--dry-run", "npm", "install", "--save-dev")
            record("flags-only-dry-run", not marker.exists(),
                   f"exit={completed.returncode}, manager handoff={marker.exists()}", completed)

    (output / "results.json").write_text(json.dumps(results, indent=2)+"\n")
    failures = sum(not item["passed"] for item in results)
    print(f"{len(results)-failures}/{len(results)} contracts passed; {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
