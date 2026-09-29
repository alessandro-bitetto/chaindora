package gate

import (
	"context"
	"errors"
	"testing"
)

// stubProvenance is the test fixture for ProvenanceProbe.
type stubProvenance struct {
	hasProv bool
	anyProv bool
	hasErr  error
	anyErr  error
}

func (s stubProvenance) HasProvenance(_ context.Context, _, _ string) (bool, error) {
	return s.hasProv, s.hasErr
}
func (s stubProvenance) AnyVersionHasProvenance(_ context.Context, _ string) (bool, error) {
	return s.anyProv, s.anyErr
}

var _ ProvenanceProbe = stubProvenance{}

func provenanceProbesWith(eco string, probe ProvenanceProbe) *Probes {
	p := NewProbes()
	p.RegisterProvenance(eco, probe)
	return p
}

func TestProvenance_ApprovesPresent(t *testing.T) {
	p := &ProvenanceCheck{Probes: provenanceProbesWith("npm", stubProvenance{hasProv: true})}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("provenance present should Approve, got %v", r.Verdict)
	}
}

func TestProvenance_DefaultModeApprovesWhenPublisherNeverUsedIt(t *testing.T) {
	p := &ProvenanceCheck{Probes: provenanceProbesWith("npm", stubProvenance{hasProv: false, anyProv: false})}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("no-prov + no-prior-prov should Approve, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestProvenance_DefaultModeWarnsOnRegression(t *testing.T) {
	p := &ProvenanceCheck{Probes: provenanceProbesWith("npm", stubProvenance{hasProv: false, anyProv: true})}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictWarn {
		t.Errorf("no-prov + prior-prov should Warn, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestProvenance_StrictModeBlocksAbsent(t *testing.T) {
	p := &ProvenanceCheck{Probes: provenanceProbesWith("npm", stubProvenance{hasProv: false}), Require: true}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictBlock {
		t.Errorf("strict mode no-prov should Block, got %v", r.Verdict)
	}
}

func TestProvenance_UnknownOnNetworkError(t *testing.T) {
	p := &ProvenanceCheck{Probes: provenanceProbesWith("npm", stubProvenance{hasErr: errors.New("net")})}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("network error should Unknown, got %v", r.Verdict)
	}
}

func TestProvenance_UnregisteredEcosystemPassthrough(t *testing.T) {
	p := &ProvenanceCheck{Probes: NewProbes()}
	r := p.Check(context.Background(), PackageRef{Ecosystem: "pypi", Name: "x", Version: "1.0"})
	if r.Verdict != VerdictApprove {
		t.Errorf("unregistered ecosystem should Approve passthrough, got %v", r.Verdict)
	}
}
