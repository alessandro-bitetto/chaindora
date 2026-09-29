package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDockerImage(t *testing.T) {
	cases := []struct {
		ref        string
		wantName   string
		wantVer    string
		wantPinned bool
	}{
		{"nginx", "nginx", "", false},
		{"nginx:1.25", "nginx", "1.25", false},
		{"library/nginx:1.25", "library/nginx", "1.25", false},
		{"gcr.io/distroless/static-debian12:nonroot", "gcr.io/distroless/static-debian12", "nonroot", false},
		{"localhost:5000/myimage:v1", "localhost:5000/myimage", "v1", false},
		{"localhost:5000/myimage", "localhost:5000/myimage", "", false},
		{"nginx@sha256:abcdef0123", "nginx", "sha256:abcdef0123", true},
		{"ubuntu:latest", "ubuntu", "latest", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		gotName, gotVer, gotPinned := parseDockerImage(c.ref)
		if gotName != c.wantName || gotVer != c.wantVer || gotPinned != c.wantPinned {
			t.Errorf("parseDockerImage(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.ref, gotName, gotVer, gotPinned, c.wantName, c.wantVer, c.wantPinned)
		}
	}
}

func TestParseDockerfile(t *testing.T) {
	content := `# Multi-stage Dockerfile fixture
FROM golang:1.22 AS builder
RUN go build

FROM --platform=linux/amd64 alpine:3.18
COPY --from=builder /out /app

FROM scratch
COPY --from=builder /out /app

FROM gcr.io/distroless/static-debian12 AS runtime

FROM ${BASE_IMAGE}
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "Dockerfile")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseDockerfile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"golang":                            "1.22",
		"alpine":                            "3.18",
		"gcr.io/distroless/static-debian12": "",
	}
	if len(pkgs) != len(want) {
		t.Fatalf("got %d packages, want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for _, p := range pkgs {
		w, ok := want[p.Name]
		if !ok {
			t.Errorf("unexpected %s@%s; want one of %v", p.Name, p.Version, want)
			continue
		}
		if p.Version != w {
			t.Errorf("%s: got version %q, want %q", p.Name, p.Version, w)
		}
		if p.Ecosystem != EcosystemDocker {
			t.Errorf("%s: wrong ecosystem %q", p.Name, p.Ecosystem)
		}
	}
}

func TestParseDockerImageRefsCompose(t *testing.T) {
	content := `version: '3.8'
services:
  web:
    image: nginx:1.25
    ports: ["80:80"]
  db:
    image: postgres:15.4
  cache:
    image: redis@sha256:deadbeef0123456789
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseDockerImageRefs(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		v      string
		pinned bool
	}{
		"nginx":    {"1.25", false},
		"postgres": {"15.4", false},
		"redis":    {"sha256:deadbeef0123456789", true},
	}
	if len(pkgs) != len(want) {
		t.Fatalf("got %d, want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for _, p := range pkgs {
		w, ok := want[p.Name]
		if !ok || p.Version != w.v || p.Pinned != w.pinned {
			t.Errorf("unexpected %s@%s pinned=%v; want %v", p.Name, p.Version, p.Pinned, want)
		}
	}
}
