package gate

// Opt-in contract tests against REAL package managers. All package content is
// generated below: metadata and constant values only, with no install hooks,
// build scripts, executable payloads, or public-registry dependencies.
// Run in network-disabled containers; see docs/environment-testing.md.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const fixtureRoot = "chaindora-fixture-root"
const fixtureLeaf = "chaindora-fixture-leaf"

func TestRealPackageManagers(t *testing.T) {
	if os.Getenv("CHAINDORA_REAL_PM_TESTS") != "1" {
		t.Skip("opt in with CHAINDORA_REAL_PM_TESTS=1; use isolated toolchains")
	}
	selected := strings.Split(os.Getenv("CHAINDORA_TEST_MANAGERS"), ",")
	known := ",npm,yarn,pnpm,bun,deno,pip,pip3,poetry,uv,pipenv,pdm,dotnet,paket,go,cargo,"
	for _, manager := range selected {
		if manager == "" || !strings.Contains(known, ","+manager+",") {
			t.Fatalf("explicit CHAINDORA_TEST_MANAGERS selection required; invalid manager %q", manager)
		}
		t.Run(manager, func(t *testing.T) {
			bin := os.Getenv("CHAINDORA_TEST_BIN_" + strings.ToUpper(manager))
			if bin == "" {
				var err error
				bin, err = exec.LookPath(manager)
				if err != nil {
					t.Fatal(err) // A selected but missing manager must not silently skip.
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			versionArgs := []string{"--version"}
			if manager == "go" {
				versionArgs = []string{"version"}
			}
			out, err := exec.CommandContext(ctx, bin, versionArgs...).CombinedOutput()
			if err != nil {
				t.Fatalf("toolchain preflight: %v\n%s", err, out)
			}
			t.Logf("toolchain: %s", strings.TrimSpace(string(out)))
			workspace := isolateFixtureEnvironment(t)
			var refs []PackageRef
			root, leaf, ecosystem, version := fixtureRoot, fixtureLeaf, "npm", "1.0.0"
			integrity, direct := true, true
			switch manager {
			case "npm", "yarn", "pnpm", "bun", "deno":
				registry := npmFixtureRegistry(t)
				t.Setenv("npm_config_registry", registry)
				t.Setenv("NPM_CONFIG_REGISTRY", registry)
				t.Setenv("YARN_NPM_REGISTRY_SERVER", registry)
				t.Setenv("YARN_UNSAFE_HTTP_WHITELIST", "127.0.0.1")
				t.Setenv("YARN_ENABLE_TELEMETRY", "0")
				t.Setenv("DENO_NO_UPDATE_CHECK", "1")
				args := []string{fixtureRoot + "@1.0.0"}
				switch manager {
				case "npm":
					refs, err = ResolveNPMTree(ctx, bin, args)
				case "yarn":
					refs, err = ResolveYarnTree(ctx, bin, args)
				case "pnpm":
					refs, err = ResolvePnpmTree(ctx, bin, append(args, "--registry="+registry))
				case "bun":
					refs, err = ResolveBunTree(ctx, bin, args)
					integrity = false // pm ls does not expose integrity.
				case "deno":
					// Generate the CURRENT lock format with the real manager first.
					writeFixture(t, filepath.Join(workspace, "deno.json"), []byte(`{"imports":{"fixture":"npm:`+fixtureRoot+`@1.0.0"}}`))
					writeFixture(t, filepath.Join(workspace, "main.ts"), []byte(`import "fixture";`))
					runFixtureCommand(t, ctx, workspace, bin, "cache", "--lock=deno.lock", "main.ts")
					refs, err = ResolveDenoTree(ctx, bin, workspace)
					direct = false // Current adapter does not label direct packages.
				}
			case "pip", "pip3", "poetry", "uv", "pipenv", "pdm":
				ecosystem = "pypi"
				registry, wheels := pythonFixtureRegistry(t)
				t.Setenv("PIP_CONFIG_FILE", os.DevNull)
				t.Setenv("PIP_DISABLE_PIP_VERSION_CHECK", "1")
				t.Setenv("PIP_INDEX_URL", registry+"/simple/")
				t.Setenv("PIP_EXTRA_INDEX_URL", "")
				t.Setenv("PIP_ONLY_BINARY", ":all:")
				t.Setenv("UV_DEFAULT_INDEX", registry+"/simple/")
				t.Setenv("UV_PYTHON_DOWNLOADS", "never")
				t.Setenv("PIPENV_PYPI_MIRROR", registry+"/simple/")
				t.Setenv("PIPENV_DEFAULT_PYTHON_VERSION", "3.13")
				t.Setenv("PIPENV_YES", "1")
				t.Setenv("PDM_PYPI_URL", registry+"/simple/")
				t.Setenv("PDM_CHECK_UPDATE", "false")
				t.Setenv("POETRY_VIRTUALENVS_CREATE", "false")
				args := []string{fixtureRoot + "==1.0.0"}
				switch manager {
				case "pip", "pip3":
					refs, err = ResolvePipTree(ctx, bin, append(args, "--no-index", "--find-links", wheels))
				case "uv":
					refs, err = ResolveUVTree(ctx, bin, args)
				case "pipenv":
					refs, err = ResolvePipenvTree(ctx, bin, args)
				case "pdm":
					refs, err = ResolvePDMTree(ctx, bin, args)
				case "poetry":
					// Poetry has no environment override for its primary package
					// source. This wrapper adds ONLY fixture-source configuration,
					// then execs the real Poetry with the original arguments.
					python, lookupErr := exec.LookPath("python3")
					if lookupErr != nil {
						t.Fatal(lookupErr)
					}
					wrapper := filepath.Join(workspace, "poetry-fixture-source")
					script := fmt.Sprintf("#!%s\nimport os, pathlib, sys\np = pathlib.Path('pyproject.toml')\ns = p.read_text()\nif '[[tool.poetry.source]]' not in s:\n p.write_text(s + '\\n[[tool.poetry.source]]\\nname = \"fixture\"\\nurl = \"' + os.environ['CHAINDORA_FIXTURE_PYPI'] + '\"\\npriority = \"primary\"\\n')\nos.execv(os.environ['CHAINDORA_REAL_POETRY'], [os.environ['CHAINDORA_REAL_POETRY']] + sys.argv[1:])\n", python)
					writeFixture(t, wrapper, []byte(script))
					if err := os.Chmod(wrapper, 0o700); err != nil {
						t.Fatal(err)
					}
					t.Setenv("CHAINDORA_FIXTURE_PYPI", registry+"/simple/")
					t.Setenv("CHAINDORA_REAL_POETRY", bin)
					refs, err = ResolvePoetryTree(ctx, wrapper, []string{fixtureRoot + "@1.0.0"})
				}
			case "go":
				ecosystem, version = "go", "v1.0.0"
				root, leaf = "example.invalid/"+fixtureRoot, "example.invalid/"+fixtureLeaf
				proxy := goFixtureProxy(t, root, leaf)
				t.Setenv("GOPROXY", proxy)
				t.Setenv("GOSUMDB", "off") // Locally generated modules have no public sumdb entries.
				t.Setenv("GONOSUMDB", "*")
				t.Setenv("GONOPROXY", "")
				t.Setenv("GOPRIVATE", "")
				t.Setenv("GOTOOLCHAIN", "local")
				refs, err = ResolveGoModTree(ctx, bin, []string{root + "@v1.0.0"})
			case "cargo":
				ecosystem = "crates"
				registry := cargoFixtureRegistry(t)
				config := fmt.Sprintf("[source.crates-io]\nreplace-with = 'fixture'\n[source.fixture]\nregistry = 'sparse+%s/index/'\n", registry)
				writeFixture(t, filepath.Join(os.Getenv("CARGO_HOME"), "config.toml"), []byte(config))
				refs, err = ResolveCargoTree(ctx, bin, []string{root + "@1.0.0"})
			case "dotnet", "paket":
				root, leaf, ecosystem = "Chaindora.Fixture.Root", "Chaindora.Fixture.Leaf", "nuget"
				feed := nugetFixtureFeed(t, root, leaf)
				config := `<configuration><packageSources><clear/><add key="fixture" value="` + feed + `"/></packageSources><packageSourceMapping><clear/></packageSourceMapping></configuration>`
				writeFixture(t, filepath.Join(os.Getenv("HOME"), ".nuget", "NuGet", "NuGet.Config"), []byte(config))
				t.Setenv("DOTNET_CLI_HOME", os.Getenv("HOME"))
				t.Setenv("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
				t.Setenv("DOTNET_NOLOGO", "1")
				t.Setenv("DOTNET_ROLL_FORWARD", "Major")
				if manager == "dotnet" {
					refs, err = ResolveNuGetTree(ctx, bin, []string{root, "--version", "1.0.0"})
				} else {
					writeFixture(t, filepath.Join(workspace, "paket.dependencies"), []byte("source "+feed+"\nnuget "+root+" 1.0.0\n"))
					runFixtureCommand(t, ctx, workspace, bin, "update")
					refs, err = ResolvePaketTree(ctx, bin, workspace)
					integrity, direct = false, false
				}
			}
			if err != nil {
				t.Fatalf("resolver: %v", err)
			}
			t.Logf("resolved: %+v", refs)
			assertFixtureClosure(t, refs, root, leaf, ecosystem, version, integrity, direct)
			// Synthetic policy data, not a malicious package: deny the benign
			// leaf to verify that the resolved transitive reaches gate policy.
			blocked := false
			for _, check := range Run(ctx, []Checker{fixtureDenyLeaf{leaf: leaf}}, refs) {
				allowed, verdict := Strict().Decide(check)
				if !allowed && verdict == VerdictBlock {
					blocked = true
				}
			}
			if !blocked {
				t.Error("denied transitive dependency never blocked the policy")
			}
		})
	}
}

// The only hook used by this test writes a constant to a designated temporary
// file. It reads no credentials, starts no network request, and changes nothing
// outside the fixture directory. Run this test in a network-disabled container.
func TestRealLifecycleSuppression(t *testing.T) {
	if os.Getenv("CHAINDORA_REAL_PM_TESTS") != "1" || os.Getenv("CHAINDORA_TEST_LIFECYCLE") != "1" {
		t.Skip("opt-in lifecycle sentinel test; run in an isolated container")
	}
	for _, manager := range strings.Split(os.Getenv("CHAINDORA_TEST_MANAGERS"), ",") {
		if manager != "npm" && manager != "yarn" && manager != "pnpm" && manager != "bun" && manager != "deno" {
			continue
		}
		t.Run(manager, func(t *testing.T) {
			bin := os.Getenv("CHAINDORA_TEST_BIN_" + strings.ToUpper(manager))
			if bin == "" {
				var err error
				bin, err = exec.LookPath(manager)
				if err != nil {
					t.Fatal(err)
				}
			}
			dir := isolateFixtureEnvironment(t)
			marker := filepath.Join(dir, "harmless-hook-ran.txt")
			t.Setenv("CHAINDORA_FIXTURE_SENTINEL", marker)
			hook := `node -e "require('fs').writeFileSync(process.env.CHAINDORA_FIXTURE_SENTINEL, 'harmless fixture hook ran')"`
			if manager == "bun" {
				hook = strings.Replace(hook, "node -e", "bun -e", 1)
			}
			if manager == "deno" {
				hook = `deno eval "Deno.writeTextFileSync(Deno.env.get('CHAINDORA_FIXTURE_SENTINEL'), 'harmless fixture hook ran')"`
			}
			registry := npmFixtureRegistry(t, hook)
			t.Setenv("npm_config_registry", registry)
			t.Setenv("NPM_CONFIG_REGISTRY", registry)
			t.Setenv("YARN_NPM_REGISTRY_SERVER", registry)
			t.Setenv("YARN_UNSAFE_HTTP_WHITELIST", "127.0.0.1")
			t.Setenv("YARN_ENABLE_TELEMETRY", "0")
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			args := []string{fixtureRoot + "@1.0.0"}
			var err error
			switch manager {
			case "npm":
				_, err = ResolveNPMTree(ctx, bin, args)
			case "yarn":
				_, err = ResolveYarnTree(ctx, bin, args)
			case "pnpm":
				_, err = ResolvePnpmTree(ctx, bin, append(args, "--registry="+registry))
			case "bun":
				_, err = ResolveBunTree(ctx, bin, args)
			case "deno":
				writeFixture(t, filepath.Join(dir, "deno.json"), []byte(`{"imports":{"fixture":"npm:`+fixtureRoot+`@1.0.0"},"nodeModulesDir":"auto"}`))
				_, err = ResolveDenoTree(ctx, bin, dir)
			}
			if err != nil {
				t.Errorf("resolver: %v", err)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Error("PREVENTION FAILURE: harmless lifecycle hook ran during resolution, before approval")
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			} else {
				t.Log("sentinel hook did not run")
			}
		})
	}
}

type fixtureDenyLeaf struct{ leaf string }

func (fixtureDenyLeaf) Name() string { return "fixture-deny-leaf" }
func (c fixtureDenyLeaf) Check(_ context.Context, ref PackageRef) CheckResult {
	v := VerdictApprove
	if ref.Name == c.leaf {
		v = VerdictBlock
	}
	return CheckResult{Checker: c.Name(), Verdict: v, Reason: "synthetic test policy"}
}

func assertFixtureClosure(t *testing.T, refs []PackageRef, root, leaf, ecosystem, version string, integrity, direct bool) {
	t.Helper()
	if len(refs) != 2 {
		t.Errorf("want exactly root and transitive leaf; got %d packages", len(refs))
	}
	seen := map[string]bool{}
	for _, ref := range refs {
		if seen[ref.Name] {
			t.Errorf("duplicate package %q", ref.Name)
		}
		seen[ref.Name] = true
		if ref.Name != root && ref.Name != leaf {
			t.Errorf("unexpected package %q", ref.Name)
		}
		if ref.Ecosystem != ecosystem || ref.Version != version {
			t.Errorf("wrong identity: %+v", ref)
		}
		if direct && ref.Direct != (ref.Name == root) {
			t.Errorf("wrong direct/transitive flag: %+v", ref)
		}
		if integrity && ref.Integrity == "" {
			t.Errorf("lost available checksum: %+v", ref)
		}
	}
	for _, name := range []string{root, leaf} {
		if !seen[name] {
			t.Errorf("missing %s", name)
		}
	}
}

func isolateFixtureEnvironment(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, key := range []string{"HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "npm_config_cache", "NPM_CONFIG_CACHE", "YARN_CACHE_FOLDER", "PNPM_HOME", "GOMODCACHE", "GOCACHE", "CARGO_HOME", "UV_CACHE_DIR", "PIP_CACHE_DIR", "NUGET_PACKAGES", "DENO_DIR"} {
		value := filepath.Join(dir, key)
		if err := os.MkdirAll(value, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv(key, value)
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, "")
	}
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	t.Setenv("CI", "1")
	t.Setenv("COREPACK_ENABLE_NETWORK", "0")
	t.Setenv("COREPACK_ENABLE_PROJECT_SPEC", "0")
	t.Setenv("COREPACK_DEFAULT_TO_LATEST", "0")
	t.Setenv("npm_config_userconfig", os.DevNull)
	t.Setenv("npm_config_globalconfig", filepath.Join(dir, "empty-npmrc"))
	writeFixture(t, filepath.Join(dir, "empty-npmrc"), nil)
	// Keep every resolver's temporary project under our own tree as well.
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	// Go makes extracted module directories read-only. Restore permissions
	// only inside this generated test tree so TempDir can remove its contents.
	t.Cleanup(func() {
		_ = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if entry.IsDir() {
				return os.Chmod(path, 0o700)
			}
			return os.Chmod(path, 0o600)
		})
	})
	return dir
}

func runFixtureCommand(t *testing.T, ctx context.Context, dir, bin string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture setup %s %v: %v\n%s", bin, args, err, out)
	}
}

func writeFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func fixtureJSON(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// makeFixtureServer serves a fixed in-memory map. It never proxies requests.
func makeFixtureServer(t *testing.T, build func(string) map[string][]byte) string {
	t.Helper()
	var files map[string][]byte
	var mu sync.Mutex
	var requests []string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.URL.Path)
		mu.Unlock()
		data, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/simple/") {
			w.Header().Set("Content-Type", "text/html")
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		_, _ = w.Write(data)
	}))
	// The listener already has its address before handlers start.
	files = build("http://" + server.Listener.Addr().String())
	server.Start()
	t.Cleanup(func() {
		server.Close()
		if t.Failed() {
			mu.Lock()
			defer mu.Unlock()
			t.Logf("fixture requests: %v", requests)
		}
	})
	return server.URL
}

func fixtureZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func fixtureTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func npmFixtureRegistry(t *testing.T, hook ...string) string {
	return makeFixtureServer(t, func(base string) map[string][]byte {
		files := map[string][]byte{}
		for _, name := range []string{fixtureRoot, fixtureLeaf} {
			manifest := map[string]any{"name": name, "version": "1.0.0", "main": "index.js", "description": "Generated harmless test fixture", "license": "MIT"}
			if name == fixtureRoot {
				manifest["dependencies"] = map[string]string{fixtureLeaf: "1.0.0"}
				if len(hook) > 0 {
					manifest["scripts"] = map[string]string{"postinstall": hook[0]}
				}
			}
			archive := fixtureTar(t, map[string][]byte{"package/package.json": fixtureJSON(t, manifest), "package/index.js": []byte("module.exports = 42;\n")})
			path := "/" + name + "/-/" + name + "-1.0.0.tgz"
			files[path] = archive
			hash := sha512.Sum512(archive)
			manifest["dist"] = map[string]string{"tarball": base + path, "integrity": "sha512-" + base64.StdEncoding.EncodeToString(hash[:])}
			files["/"+name] = fixtureJSON(t, map[string]any{"name": name, "dist-tags": map[string]string{"latest": "1.0.0"}, "versions": map[string]any{"1.0.0": manifest}, "time": map[string]string{"created": "2024-01-01T00:00:00Z", "modified": "2024-01-01T00:00:00Z", "1.0.0": "2024-01-01T00:00:00Z"}})
			files["/"+name+"/1.0.0"] = fixtureJSON(t, manifest)
		}
		return files
	})
}

func pythonFixtureRegistry(t *testing.T) (string, string) {
	wheels := t.TempDir()
	base := makeFixtureServer(t, func(base string) map[string][]byte {
		files := map[string][]byte{}
		for _, name := range []string{fixtureRoot, fixtureLeaf} {
			module := strings.ReplaceAll(name, "-", "_")
			dist := module + "-1.0.0.dist-info/"
			metadata := "Metadata-Version: 2.1\nName: " + name + "\nVersion: 1.0.0\nRequires-Python: >=3.8\n"
			if name == fixtureRoot {
				metadata += "Requires-Dist: " + fixtureLeaf + "==1.0.0\n"
			}
			entries := map[string][]byte{dist + "METADATA": []byte(metadata + "\n"), dist + "WHEEL": []byte("Wheel-Version: 1.0\nGenerator: chaindora-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"), module + "/__init__.py": []byte("VALUE = 42\n")}
			var record strings.Builder
			for path, data := range entries {
				hash := sha256.Sum256(data)
				fmt.Fprintf(&record, "%s,sha256=%s,%d\n", path, base64.RawURLEncoding.EncodeToString(hash[:]), len(data))
			}
			record.WriteString(dist + "RECORD,,\n")
			entries[dist+"RECORD"] = []byte(record.String())
			wheel := fixtureZip(t, entries)
			filename := module + "-1.0.0-py3-none-any.whl"
			writeFixture(t, filepath.Join(wheels, filename), wheel)
			files["/files/"+filename] = wheel
			hash := sha256.Sum256(wheel)
			files["/simple/"+name+"/"] = []byte(fmt.Sprintf(`<html><a href="%s/files/%s#sha256=%x">%s</a></html>`, base, filename, hash, filename))
		}
		return files
	})
	return base, wheels
}

func goFixtureProxy(t *testing.T, root, leaf string) string {
	return makeFixtureServer(t, func(_ string) map[string][]byte {
		files := map[string][]byte{}
		for _, name := range []string{root, leaf} {
			mod := "module " + name + "\n\ngo 1.22\n"
			if name == root {
				mod += "\nrequire " + leaf + " v1.0.0\n"
			}
			prefix := "/" + name + "/@v/"
			info := []byte(`{"Version":"v1.0.0","Time":"2024-01-01T00:00:00Z"}`)
			files[prefix+"list"] = []byte("v1.0.0\n")
			files[prefix+"v1.0.0.info"] = info
			files["/"+name+"/@latest"] = info
			files[prefix+"v1.0.0.mod"] = []byte(mod)
			files[prefix+"v1.0.0.zip"] = fixtureZip(t, map[string][]byte{name + "@v1.0.0/go.mod": []byte(mod), name + "@v1.0.0/fixture.go": []byte("package fixture\nconst Value = 42\n")})
		}
		return files
	})
}

func cargoFixtureRegistry(t *testing.T) string {
	return makeFixtureServer(t, func(base string) map[string][]byte {
		files := map[string][]byte{"/index/config.json": fixtureJSON(t, map[string]any{"dl": base + "/crates", "api": base, "auth-required": false})}
		for _, name := range []string{fixtureRoot, fixtureLeaf} {
			manifest := "[package]\nname = '" + name + "'\nversion = '1.0.0'\nedition = '2021'\n"
			deps := []map[string]any{}
			if name == fixtureRoot {
				manifest += "[dependencies]\n" + fixtureLeaf + " = '=1.0.0'\n"
				deps = append(deps, map[string]any{"name": fixtureLeaf, "req": "=1.0.0", "features": []string{}, "optional": false, "default_features": true, "target": nil, "kind": "normal", "registry": nil})
			}
			crate := fixtureTar(t, map[string][]byte{name + "-1.0.0/Cargo.toml": []byte(manifest), name + "-1.0.0/src/lib.rs": []byte("pub const VALUE: u8 = 42;\n")})
			hash := sha256.Sum256(crate)
			files["/crates/"+name+"/1.0.0/download"] = crate
			files["/index/"+name[:2]+"/"+name[2:4]+"/"+name] = append(fixtureJSON(t, map[string]any{"name": name, "vers": "1.0.0", "deps": deps, "cksum": fmt.Sprintf("%x", hash), "features": map[string]any{}, "yanked": false}), '\n')
		}
		return files
	})
}

func nugetFixtureFeed(t *testing.T, root, leaf string) string {
	feed := t.TempDir()
	for _, name := range []string{root, leaf} {
		deps := ""
		if name == root {
			deps = `<dependencies><dependency id="` + leaf + `" version="[1.0.0]"/></dependencies>`
		}
		nuspec := `<?xml version="1.0"?><package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata><id>` + name + `</id><version>1.0.0</version><authors>Chaindora tests</authors><description>Generated harmless fixture</description>` + deps + `</metadata></package>`
		data := fixtureZip(t, map[string][]byte{name + ".nuspec": []byte(nuspec), "lib/net8.0/_._": nil})
		writeFixture(t, filepath.Join(feed, name+".1.0.0.nupkg"), data)
	}
	return feed
}
