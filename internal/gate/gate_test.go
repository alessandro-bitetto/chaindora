package gate

import (
	"context"
	"testing"
)

type fakeChecker struct {
	name   string
	result CheckResult
}

func (f fakeChecker) Name() string                                   { return f.name }
func (f fakeChecker) Check(context.Context, PackageRef) CheckResult { return f.result }

func TestDecision_WorstVerdictWins(t *testing.T) {
	cases := []struct {
		name     string
		verdicts []Verdict
		want     Verdict
	}{
		{"all approve", []Verdict{VerdictApprove, VerdictApprove}, VerdictApprove},
		{"warn beats approve", []Verdict{VerdictApprove, VerdictWarn}, VerdictWarn},
		{"block beats warn", []Verdict{VerdictWarn, VerdictBlock}, VerdictBlock},
		{"block beats unknown", []Verdict{VerdictUnknown, VerdictBlock}, VerdictBlock},
		{"unknown beats approve when nothing else fires", []Verdict{VerdictApprove, VerdictUnknown}, VerdictUnknown},
		{"warn beats unknown", []Verdict{VerdictUnknown, VerdictWarn}, VerdictWarn},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pc := PackageCheck{}
			for _, v := range c.verdicts {
				pc.Results = append(pc.Results, CheckResult{Verdict: v})
			}
			if got := pc.Decision(); got != c.want {
				t.Errorf("decision: got %v, want %v", got, c.want)
			}
		})
	}
}

func TestPolicy_Strict(t *testing.T) {
	p := Strict()
	cases := []struct {
		verdict Verdict
		want    bool
	}{
		{VerdictApprove, true},
		{VerdictWarn, false},
		{VerdictBlock, false},
		{VerdictUnknown, false},
	}
	for _, c := range cases {
		pc := PackageCheck{Results: []CheckResult{{Verdict: c.verdict}}}
		allow, _ := p.Decide(pc)
		if allow != c.want {
			t.Errorf("strict policy on %v: allow=%v, want %v", c.verdict, allow, c.want)
		}
	}
}

func TestPolicy_Lenient_AllowsWarn(t *testing.T) {
	p := Lenient()
	pc := PackageCheck{Results: []CheckResult{{Verdict: VerdictWarn}}}
	if allow, _ := p.Decide(pc); !allow {
		t.Errorf("lenient policy should allow warn")
	}
	pc = PackageCheck{Results: []CheckResult{{Verdict: VerdictBlock}}}
	if allow, _ := p.Decide(pc); allow {
		t.Errorf("lenient policy must still block on Block")
	}
}

func TestRun_AppliesEveryCheckerPerPackage(t *testing.T) {
	checkers := []Checker{
		fakeChecker{name: "a", result: CheckResult{Checker: "a", Verdict: VerdictApprove}},
		fakeChecker{name: "b", result: CheckResult{Checker: "b", Verdict: VerdictWarn, Reason: "looks fishy"}},
	}
	pkgs := []PackageRef{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", Direct: true},
	}
	out := Run(context.Background(), checkers, pkgs)
	if len(out) != 1 {
		t.Fatalf("expected 1 package check, got %d", len(out))
	}
	if len(out[0].Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(out[0].Results))
	}
	if out[0].Decision() != VerdictWarn {
		t.Errorf("aggregate decision: got %v, want warn", out[0].Decision())
	}
}

func TestPackageRef_String(t *testing.T) {
	r := PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}
	if got := r.String(); got != "npm:lodash@4.17.21" {
		t.Errorf("got %q", got)
	}
}

func TestSummarize(t *testing.T) {
	checks := []PackageCheck{
		{Results: []CheckResult{{Verdict: VerdictApprove}}},
		{Results: []CheckResult{{Verdict: VerdictApprove}}},
		{Results: []CheckResult{{Verdict: VerdictBlock}}},
		{Results: []CheckResult{{Verdict: VerdictWarn}}},
	}
	got := Summarize(checks)
	want := "approve=2 warn=1 block=1"
	if got != want {
		t.Errorf("summarize: got %q, want %q", got, want)
	}
}
