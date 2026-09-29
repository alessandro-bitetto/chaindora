package cli

import (
	"path/filepath"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/gate"
)

func TestEmptyGateTreeNeverApproves(t *testing.T) {
	for _, policy := range []gate.Policy{gate.Strict(), {AllowOnWarn: true, AllowOnUnknown: true}} {
		if got := overallVerdict(nil, policy); got != gate.VerdictUnknown {
			t.Fatalf("empty tree yielded %s", got)
		}
	}
}

func TestDryRunCannotReachFinalProcess(t *testing.T) {
	previous := gateExecDryRun
	t.Cleanup(func() { gateExecDryRun = previous })
	gateExecDryRun = true
	// A nonexistent manager would fail if execReal attempted any process start.
	if err := execReal(filepath.Join(t.TempDir(), "must-not-execute"), []string{"ci"}); err != nil {
		t.Fatal(err)
	}
}
