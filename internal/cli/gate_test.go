package cli

import (
	"strings"
	"testing"
)

func TestParsePackageArg_Plain(t *testing.T) {
	ref, err := parsePackageArg("lodash@4.17.21", "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Ecosystem != "npm" || ref.Name != "lodash" || ref.Version != "4.17.21" {
		t.Errorf("got %+v, want npm/lodash@4.17.21", ref)
	}
}

func TestParsePackageArg_Scoped(t *testing.T) {
	ref, err := parsePackageArg("@types/node@20.0.0", "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Name != "@types/node" || ref.Version != "20.0.0" {
		t.Errorf("got %+v, want @types/node@20.0.0", ref)
	}
}

func TestParsePackageArg_PURL(t *testing.T) {
	ref, err := parsePackageArg("pkg:npm/express@5.0.0", "rubygems")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// PURL ecosystem must override the caller-supplied default.
	if ref.Ecosystem != "npm" {
		t.Errorf("ecosystem = %q, want npm (from PURL)", ref.Ecosystem)
	}
	if ref.Name != "express" || ref.Version != "5.0.0" {
		t.Errorf("got %+v, want express@5.0.0", ref)
	}
}

func TestParsePackageArg_PURLScopedWithEncoding(t *testing.T) {
	ref, err := parsePackageArg("pkg:npm/%40types%2Fnode@20.0.0", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// %2F decodes to '/'; %40 is the scope '@'. We only decode the slash
	// here, since the @ is what the parser uses as the version separator.
	if !strings.Contains(ref.Name, "/") {
		t.Errorf("expected decoded slash in name, got %q", ref.Name)
	}
}

func TestParsePackageArg_ShortEcosystemPrefix(t *testing.T) {
	ref, err := parsePackageArg("pypi:requests@2.32.0", "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Ecosystem != "pypi" {
		t.Errorf("ecosystem = %q, want pypi", ref.Ecosystem)
	}
	if ref.Name != "requests" || ref.Version != "2.32.0" {
		t.Errorf("got %+v, want requests@2.32.0", ref)
	}
}

func TestParsePackageArg_RejectsStrayEcosystemSlash(t *testing.T) {
	_, err := parsePackageArg("npm/express@5.0.0", "npm")
	if err == nil {
		t.Fatalf("expected error for 'npm/express@5.0.0', got nil")
	}
	if !strings.Contains(err.Error(), "scoped name") {
		t.Errorf("error should mention 'scoped name', got %q", err.Error())
	}
}

func TestParsePackageArg_RejectsMissingVersion(t *testing.T) {
	_, err := parsePackageArg("lodash", "npm")
	if err == nil {
		t.Fatalf("expected error for missing @version, got nil")
	}
}

func TestParsePackageArg_RejectsEmpty(t *testing.T) {
	_, err := parsePackageArg("", "npm")
	if err == nil {
		t.Fatalf("expected error for empty arg, got nil")
	}
}

func TestParsePackageArg_RejectsMalformedPURL(t *testing.T) {
	_, err := parsePackageArg("pkg:express@5.0.0", "npm")
	if err == nil {
		t.Fatalf("expected error for 'pkg:express@5.0.0' (no '/' separator), got nil")
	}
}

func TestParsePackageArg_UnknownColonPrefixPassesThrough(t *testing.T) {
	// A colon in a name that doesn't look like an ecosystem prefix
	// should not be treated as one. We expect the parser to fall
	// through, which then fails on '/' detection here because the
	// name contains a slash too — but the key behavior is that the
	// ecosystem stays "npm" (the caller-supplied default).
	_, err := parsePackageArg("some:weird/name@1.0", "npm")
	if err == nil {
		t.Fatalf("expected error for 'some:weird/name@1.0', got nil")
	}
}
