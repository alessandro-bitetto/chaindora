package gate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_FindsInCwd(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "chaindora.yml"), []byte(`
cooldown_hours: 48
allow:
  npm:
    - "lodash@4.17.21"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("expected config, got nil")
	}
	if c.CooldownHours != 48 {
		t.Errorf("cooldown_hours: got %d, want 48", c.CooldownHours)
	}
}

func TestLoadConfig_WalksUpToParent(t *testing.T) {
	tmp := t.TempDir()
	deep := filepath.Join(tmp, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "chaindora.yml"), []byte("cooldown_hours: 24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(deep)
	if err != nil {
		t.Fatal(err)
	}
	if c == nil || c.CooldownHours != 24 {
		t.Errorf("config walk-up failed: %+v", c)
	}
}

func TestLoadConfig_NoFileReturnsNil(t *testing.T) {
	tmp := t.TempDir()
	c, err := LoadConfig(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if c != nil {
		t.Errorf("expected nil config for missing file, got %+v", c)
	}
}

func TestIsAllowed(t *testing.T) {
	c := &Config{
		Allow: map[string][]string{
			"npm": {"lodash@4.17.21", "@my-org/utils", "react"},
		},
	}
	cases := []struct {
		ref  PackageRef
		want bool
	}{
		{PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}, true},
		{PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}, false}, // wrong version
		{PackageRef{Ecosystem: "npm", Name: "@my-org/utils", Version: "1.0.0"}, true},
		{PackageRef{Ecosystem: "npm", Name: "@my-org/utils", Version: "9.9.9"}, true}, // any version
		{PackageRef{Ecosystem: "npm", Name: "react", Version: "18.0.0"}, true},
		{PackageRef{Ecosystem: "npm", Name: "vue", Version: "3.0"}, false},
		{PackageRef{Ecosystem: "pypi", Name: "lodash", Version: "4.17.21"}, false}, // ecosystem-scoped
	}
	for _, tc := range cases {
		if got := c.IsAllowed(tc.ref); got != tc.want {
			t.Errorf("IsAllowed(%v) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}

func TestIsDenied(t *testing.T) {
	c := &Config{
		Deny: map[string][]string{"npm": {"moment"}},
	}
	if !c.IsDenied(PackageRef{Ecosystem: "npm", Name: "moment", Version: "2.29.4"}) {
		t.Errorf("moment should be denied")
	}
	if c.IsDenied(PackageRef{Ecosystem: "npm", Name: "date-fns", Version: "2.0.0"}) {
		t.Errorf("date-fns should not be denied")
	}
}

func TestAllowlistChecker_DeniedBlocks(t *testing.T) {
	ch := &AllowlistChecker{Config: &Config{
		Deny: map[string][]string{"npm": {"moment"}},
	}}
	r := ch.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "moment", Version: "2.29.4"})
	if r.Verdict != VerdictBlock {
		t.Errorf("denied package should Block, got %v", r.Verdict)
	}
}

func TestAllowlistChecker_AllowedApproves(t *testing.T) {
	ch := &AllowlistChecker{Config: &Config{
		Allow: map[string][]string{"npm": {"lodash"}},
	}}
	r := ch.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})
	if r.Verdict != VerdictApprove {
		t.Errorf("allowed package should Approve, got %v", r.Verdict)
	}
	if r.Reason != "explicitly allowed in chaindora.yml" {
		t.Errorf("reason should call out the explicit allow, got %q", r.Reason)
	}
}

func TestAllowlistChecker_NoConfigPassthrough(t *testing.T) {
	ch := &AllowlistChecker{Config: nil}
	r := ch.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "anything", Version: "1.0.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("no config should pass through as Approve so other checkers still run, got %v", r.Verdict)
	}
}
