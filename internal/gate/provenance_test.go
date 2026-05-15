package gate

import (
	"context"
	"errors"
	"testing"
)

type stubProvenance struct {
	hasProv   bool
	anyProv   bool
	hasErr    error
	anyErr    error
}

func (s stubProvenance) HasProvenance(_ context.Context, _, _ string) (bool, error) {
	return s.hasProv, s.hasErr
}
func (s stubProvenance) AnyVersionHasProvenance(_ context.Context, _ string) (bool, error) {
	return s.anyProv, s.anyErr
}

func TestProvenance_ApprovesPresent(t *testing.T) {
	p := &ProvenanceCheck{NPM: stubProvenance{hasProv: true}}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("provenance present should Approve, got %v", r.Verdict)
	}
}

func TestProvenance_DefaultModeApprovesWhenPublisherNeverUsedIt(t *testing.T) {
	p := &ProvenanceCheck{NPM: stubProvenance{hasProv: false, anyProv: false}}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("no-prov + no-prior-prov should Approve (signal-free), got %v: %q", r.Verdict, r.Reason)
	}
}

func TestProvenance_DefaultModeWarnsOnRegression(t *testing.T) {
	p := &ProvenanceCheck{NPM: stubProvenance{hasProv: false, anyProv: true}}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictWarn {
		t.Errorf("no-prov on this version + prior-prov elsewhere should Warn, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestProvenance_StrictModeBlocksAbsent(t *testing.T) {
	p := &ProvenanceCheck{NPM: stubProvenance{hasProv: false}, Require: true}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictBlock {
		t.Errorf("strict mode no-prov should Block, got %v", r.Verdict)
	}
}

func TestProvenance_UnknownOnNetworkError(t *testing.T) {
	p := &ProvenanceCheck{NPM: stubProvenance{hasErr: errors.New("net")}}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("network error should Unknown, got %v", r.Verdict)
	}
}

func TestProvenance_NonNPMPassthrough(t *testing.T) {
	p := &ProvenanceCheck{NPM: stubProvenance{}}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "pypi", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("non-npm should Approve passthrough, got %v", r.Verdict)
	}
}
