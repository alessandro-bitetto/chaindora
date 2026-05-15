package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// TestPreflight_FiltersAlreadySatisfied is the v0.8.1 motivating case:
// the saved plan says "upgrade lodash to ^4.17.21" but the user already
// has 4.18.0 installed (e.g. they ran `npm install` since the plan was
// generated). Preflight should drop the plan instead of re-running a
// command that's a no-op at best.
func TestPreflight_FiltersAlreadySatisfied(t *testing.T) {
	tmp := t.TempDir()
	mustWriteLockfile(t, tmp, map[string]string{"lodash": "4.18.0"})

	plans := []findings.FixPlan{
		{
			VulnID:          "CVE-X",
			ProjectDir:      tmp,
			PackageName:     "lodash",
			RequiredVersion: "4.17.21",
			Command:         "cd " + tmp + " && npm install lodash@^4.17.21",
			Category:        findings.FixSemiSafe,
		},
	}
	kept, skipped, notes := preflightFilterSatisfied(plans)
	if len(kept) != 0 {
		t.Errorf("expected 0 kept (lodash 4.18.0 satisfies ^4.17.21), got %d", len(kept))
	}
	if skipped != 1 {
		t.Errorf("expected skipped=1, got %d", skipped)
	}
	if len(notes) != 1 {
		t.Errorf("expected 1 note, got %d: %v", len(notes), notes)
	}
}

// TestPreflight_KeepsWhenBelowPin is the inverse: lodash 4.17.10
// does NOT satisfy ^4.17.21, so the plan stays.
func TestPreflight_KeepsWhenBelowPin(t *testing.T) {
	tmp := t.TempDir()
	mustWriteLockfile(t, tmp, map[string]string{"lodash": "4.17.10"})

	plans := []findings.FixPlan{
		{
			VulnID:          "CVE-X",
			ProjectDir:      tmp,
			PackageName:     "lodash",
			RequiredVersion: "4.17.21",
			Command:         "irrelevant",
		},
	}
	kept, skipped, _ := preflightFilterSatisfied(plans)
	if len(kept) != 1 {
		t.Errorf("expected 1 kept (4.17.10 < 4.17.21), got %d", len(kept))
	}
	if skipped != 0 {
		t.Errorf("expected skipped=0, got %d", skipped)
	}
}

// TestPreflight_KeepsWhenMajorDiffers — same package, but the
// installed major is different. We never claim cross-major
// satisfaction; the plan should stay.
func TestPreflight_KeepsWhenMajorDiffers(t *testing.T) {
	tmp := t.TempDir()
	mustWriteLockfile(t, tmp, map[string]string{"lodash": "5.0.0"})

	plans := []findings.FixPlan{
		{
			ProjectDir:      tmp,
			PackageName:     "lodash",
			RequiredVersion: "4.17.21",
			Command:         "irrelevant",
		},
	}
	kept, skipped, _ := preflightFilterSatisfied(plans)
	// Note: 5.0.0 > 4.17.21 numerically, but they're in different
	// majors — versionSatisfies returns false because constraint is
	// caret (^4.17.21 ⇒ in-major).
	if len(kept) != 1 {
		t.Errorf("expected plan kept on cross-major mismatch, got %d kept", len(kept))
	}
	if skipped != 0 {
		t.Errorf("expected no skip on cross-major, got %d", skipped)
	}
}

// TestPreflight_NoLockfilePassThrough — when there's no
// package-lock.json in ProjectDir (e.g. pip / yarn / pnpm projects),
// preflight returns "unknown" and the plan flows through unchanged.
func TestPreflight_NoLockfilePassThrough(t *testing.T) {
	tmp := t.TempDir() // empty dir, no lockfile

	plans := []findings.FixPlan{
		{
			ProjectDir:      tmp,
			PackageName:     "lodash",
			RequiredVersion: "4.17.21",
			Command:         "irrelevant",
		},
	}
	kept, skipped, _ := preflightFilterSatisfied(plans)
	if len(kept) != 1 || skipped != 0 {
		t.Errorf("unknown lockfile state must pass-through; got kept=%d skipped=%d", len(kept), skipped)
	}
}

// TestPreflight_PlansWithoutDedupKeysSkipPreflight — plans missing
// any of the three dedup keys (PackageName/ProjectDir/RequiredVersion)
// should bypass preflight entirely. This covers incident-pack
// uninstall commands and hostforensics manuals.
func TestPreflight_PlansWithoutDedupKeysSkipPreflight(t *testing.T) {
	plans := []findings.FixPlan{
		{VulnID: "A", Command: "rm -f /tmp/worm.js"},
		{VulnID: "B", PackageName: "x" /* no RequiredVersion, no ProjectDir */},
	}
	kept, skipped, _ := preflightFilterSatisfied(plans)
	if len(kept) != 2 || skipped != 0 {
		t.Errorf("plans without dedup keys must pass-through; got kept=%d skipped=%d", len(kept), skipped)
	}
}

func TestVersionSatisfies(t *testing.T) {
	cases := []struct {
		installed, required string
		want                bool
		okWant              bool
	}{
		{"4.18.0", "4.17.21", true, true},  // same major, installed > required
		{"4.17.21", "4.17.21", true, true}, // exact match
		{"4.17.20", "4.17.21", false, true},
		{"5.0.0", "4.17.21", false, true}, // different major
		{"weird", "4.17.21", false, false},
	}
	for _, c := range cases {
		got, ok := versionSatisfies(c.installed, c.required)
		if ok != c.okWant {
			t.Errorf("versionSatisfies(%q,%q) ok=%v, want %v", c.installed, c.required, ok, c.okWant)
			continue
		}
		if got != c.want {
			t.Errorf("versionSatisfies(%q,%q) = %v, want %v", c.installed, c.required, got, c.want)
		}
	}
}

func mustWriteLockfile(t *testing.T, dir string, versions map[string]string) {
	t.Helper()
	// Build a v3 package-lock.json with a single top-level package
	// and `node_modules/<name>` entries for each requested package.
	lock := `{"name":"x","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"x","version":"1.0.0"}`
	for name, ver := range versions {
		lock += `,"node_modules/` + name + `":{"version":"` + ver + `"}`
	}
	lock += `}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
}
