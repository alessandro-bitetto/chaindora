package cli

import (
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/gate"
)

// checkerOpts is the shared knob-set used by both
// `chdora gate check` and `chdora gate exec` for building their
// checker stacks. Single source of truth so the two surfaces
// can't drift in which checks they run.
type checkerOpts struct {
	SkipOSV           bool
	SkipStatic        bool
	RequireProvenance bool
	Config            *gate.Config
}

// buildCheckerStack assembles the canonical gate stack: allowlist
// (always first), OSV, cooldown, publisher-change, maintainer-
// trust, provenance, static-pattern, version-diff. Every checker
// gets the supplied Probes table — so adding a new ecosystem in
// buildGateProbes() lights up every check at once.
func buildCheckerStack(probes *gate.Probes, threshold time.Duration, opts checkerOpts) []gate.Checker {
	stack := []gate.Checker{
		&gate.AllowlistChecker{Config: opts.Config},
	}
	if !opts.SkipOSV {
		stack = append(stack, gate.NewOSVCheck())
	}
	cooldown := gate.NewCooldown(threshold)
	cooldown.Probes = probes
	stack = append(stack, cooldown)

	pub := gate.NewPublisherChange()
	pub.Probes = probes
	stack = append(stack, pub)

	maint := gate.NewMaintainerTrust()
	maint.Probes = probes
	stack = append(stack, maint)

	prov := gate.NewProvenanceCheck()
	prov.Probes = probes
	prov.Require = opts.RequireProvenance
	stack = append(stack, prov)

	// Git-URL trust evaluator (v0.11.1) fires only on
	// PackageRef{Ecosystem:"git"} entries; for every registry
	// package it's a no-op. The npm/yarn/pnpm/pip resolvers
	// emit Ecosystem:"git" when a git+url replaces the
	// canonical registry URL.
	gitChecker := gate.NewGitURLCheck()
	if opts.Config != nil {
		gitChecker.AllowedHosts = opts.Config.GitHosts
		gitChecker.AllowBranchRefs = opts.Config.AllowBranchRefs
	}
	stack = append(stack, gitChecker)

	if !opts.SkipStatic {
		ss := &gate.StaticScan{
			Probes:   probes,
			MaxBytes: 50 << 20,
			BlockAt:  3,
			WarnAt:   1,
		}
		stack = append(stack, ss)
		vd := gate.NewVersionBumpDiff()
		vd.Probes = probes
		stack = append(stack, vd)
	}
	return stack
}
