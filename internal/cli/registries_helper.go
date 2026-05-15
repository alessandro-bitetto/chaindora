package cli

import (
	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

// buildRegistryProbes constructs the npm + PyPI probes used by the
// evidence-based heuristics introduced in v0.6.0. When skip is true
// (--skip-registry flag), returns Noop probes so heuristics that need
// evidence simply don't fire. Otherwise wraps the live HTTP probes in
// the disk cache at ~/.chaindora/registry-cache.json so repeated
// audits don't hammer the registries.
//
// Called once per top-level command invocation; the same probes are
// passed through to every per-project scan in --scan-projects mode so
// the cache amortizes across the whole audit.
func buildRegistryProbes(skip bool) (npm, pypi registries.Probe) {
	if skip {
		return registries.Noop{}, registries.Noop{}
	}
	return registries.NewCached(registries.NewNPM(), "npm"),
		registries.NewCached(registries.NewPyPI(), "pypi")
}
