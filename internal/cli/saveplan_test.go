package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// setHomeForTest reroutes the chaindora data dir into a tmp dir so
// maybePromptSavePlan can actually save without writing to the real
// user's home. Sets both HOME (Unix) and USERPROFILE (Windows)
// because os.UserHomeDir reads a different env var depending on
// platform — setting only HOME makes the Windows CI matrix fail.
func setHomeForTest(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func TestMaybePromptSavePlan_DefaultYesOnEnter(t *testing.T) {
	home := setHomeForTest(t)
	plans := []findings.FixPlan{{VulnID: "X", Category: findings.FixSemiSafe, Command: "true"}}

	var stderr bytes.Buffer
	id := maybePromptSavePlan(strings.NewReader("\n"), &stderr, plans, 1, "/tmp", false, false)
	if id == "" {
		t.Fatalf("expected default-Yes (Enter) to save; stderr=%q", stderr.String())
	}
	// Plan file should exist on disk.
	if _, err := os.Stat(filepath.Join(home, ".chaindora", "fix-plans", id+".json")); err != nil {
		t.Errorf("saved plan should exist: %v", err)
	}
}

func TestMaybePromptSavePlan_YExplicit(t *testing.T) {
	setHomeForTest(t)
	plans := []findings.FixPlan{{VulnID: "X", Category: findings.FixSemiSafe, Command: "true"}}
	var stderr bytes.Buffer
	if id := maybePromptSavePlan(strings.NewReader("y\n"), &stderr, plans, 1, "/tmp", false, false); id == "" {
		t.Errorf("explicit Y should save")
	}
}

func TestMaybePromptSavePlan_DeclineWithN(t *testing.T) {
	setHomeForTest(t)
	plans := []findings.FixPlan{{VulnID: "X", Category: findings.FixSemiSafe, Command: "true"}}
	var stderr bytes.Buffer
	if id := maybePromptSavePlan(strings.NewReader("n\n"), &stderr, plans, 1, "/tmp", false, false); id != "" {
		t.Errorf("'n' should decline save, got id=%q", id)
	}
}

func TestMaybePromptSavePlan_SkipsWhenAlreadySaved(t *testing.T) {
	plans := []findings.FixPlan{{VulnID: "X", Category: findings.FixSemiSafe, Command: "true"}}
	var stderr bytes.Buffer
	// saved=true → no prompt, no save. We feed stdin "y" to prove
	// we don't even read from it.
	if id := maybePromptSavePlan(strings.NewReader("y\n"), &stderr, plans, 1, "/tmp", true, false); id != "" {
		t.Errorf("should not save when saved=true, got id=%q", id)
	}
	if stderr.Len() != 0 {
		t.Errorf("should not write any prompt to stderr when saved=true, got %q", stderr.String())
	}
}

func TestMaybePromptSavePlan_SkipsWhenFixRequested(t *testing.T) {
	plans := []findings.FixPlan{{VulnID: "X", Category: findings.FixSemiSafe, Command: "true"}}
	var stderr bytes.Buffer
	if id := maybePromptSavePlan(strings.NewReader("y\n"), &stderr, plans, 1, "/tmp", false, true); id != "" {
		t.Errorf("should not save when fixRequested=true, got id=%q", id)
	}
}

func TestMaybePromptSavePlan_NoFixesSkips(t *testing.T) {
	var stderr bytes.Buffer
	if id := maybePromptSavePlan(strings.NewReader("y\n"), &stderr, nil, 0, "/tmp", false, false); id != "" {
		t.Errorf("should not save with empty plans, got id=%q", id)
	}
}
