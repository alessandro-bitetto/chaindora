package gate

import (
	"context"
	"io"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

// VersionProbe is the per-ecosystem registry interface every gate
// checker needs. Each ecosystem (npm, PyPI, RubyGems, crates.io,
// Maven Central, ...) provides one implementation; the gate
// dispatches at Check time on PackageRef.Ecosystem.
//
// Methods are designed for ecosystem-uniform shapes. Where an
// ecosystem can't supply a particular signal (PyPI doesn't carry
// per-version publisher metadata, Maven Central doesn't expose
// release-time fields uniformly), the implementation returns
// ("", nil) or a zero value and the checker degrades to Unknown.
// Fail-closed: never return success when the underlying API
// genuinely failed.
type VersionProbe interface {
	// PublishedAtVersion returns the upload/publish time of a
	// specific (name, version). Zero time + nil error means
	// "registry returned no date for this version" (rare, but
	// possible for legacy packages).
	PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error)

	// PublisherOfVersion returns the account/identity that
	// published this specific version. Empty string + nil error
	// means "registry doesn't report this metadata for this
	// ecosystem" — checker should treat as Unknown, not Approve.
	PublisherOfVersion(ctx context.Context, name, version string) (string, error)

	// AllVersions returns the timeline of every published
	// version for the package, chronologically. Used by
	// maintainer-trust (account age, dormancy gap) and by
	// publisher-change (to find the prior version's publisher).
	AllVersions(ctx context.Context, name string) ([]registries.VersionInfo, error)

	// TarballURL returns the canonical source-archive URL for a
	// specific version. Used by static-pattern and version-diff
	// to fetch the bytes the registry will hand the user.
	TarballURL(ctx context.Context, name, version string) (string, error)

	// FetchTarball downloads the archive at the given URL into
	// dst. Implementations should cap the download size to a
	// reasonable upper bound (50 MB is the chaindora default).
	FetchTarball(ctx context.Context, url string, dst io.Writer) error
}

// ProvenanceProbe is the optional interface for ecosystems that
// support sigstore-backed publish provenance. Only npm exposes
// this today via dist.attestations; PyPI's trusted-publishers is
// shaped differently and we don't try to fit it through the same
// interface. Implementations either satisfy this OR don't; the
// checker handles absence by returning Approve for non-supporting
// ecosystems.
type ProvenanceProbe interface {
	HasProvenance(ctx context.Context, name, version string) (bool, error)
	AnyVersionHasProvenance(ctx context.Context, name string) (bool, error)
}

// Probes is the lookup table the CLI builds once and hands to
// every checker. Map key is the ecosystem string used by the
// inventory parser (PackageRef.Ecosystem). Missing-key lookup
// returns ok=false and the checker degrades to Unknown.
//
// This is the seam that lets a new ecosystem snap in without
// touching every checker: register a probe for the ecosystem,
// and every checker that uses VersionProbe (cooldown,
// publisher-change, maintainer-trust, static-pattern,
// version-diff) starts working for it.
type Probes struct {
	Version    map[string]VersionProbe
	Provenance map[string]ProvenanceProbe
}

// NewProbes returns an empty Probes ready for registration.
func NewProbes() *Probes {
	return &Probes{
		Version:    map[string]VersionProbe{},
		Provenance: map[string]ProvenanceProbe{},
	}
}

// Register adds a per-ecosystem VersionProbe. Replaces any
// existing entry for that ecosystem.
func (p *Probes) Register(ecosystem string, probe VersionProbe) {
	p.Version[ecosystem] = probe
}

// RegisterProvenance adds a per-ecosystem ProvenanceProbe.
func (p *Probes) RegisterProvenance(ecosystem string, probe ProvenanceProbe) {
	p.Provenance[ecosystem] = probe
}

// versionProbeFor canonicalizes ecosystem aliases ("pypi" / "pip")
// before lookup so callers can use either name.
func (p *Probes) versionProbeFor(ecosystem string) (VersionProbe, bool) {
	if v, ok := p.Version[canonicalEcosystem(ecosystem)]; ok {
		return v, true
	}
	return nil, false
}

func (p *Probes) provenanceProbeFor(ecosystem string) (ProvenanceProbe, bool) {
	v, ok := p.Provenance[canonicalEcosystem(ecosystem)]
	return v, ok
}

// canonicalEcosystem maps user-facing aliases to the canonical
// ecosystem name. Inventory parsers and OSV use slightly
// different spellings; we normalize at the seam.
func canonicalEcosystem(eco string) string {
	switch eco {
	case "pip":
		return "pypi"
	case "rubygems", "gem":
		return "rubygems"
	case "cargo":
		return "crates"
	case "maven-central":
		return "maven"
	}
	return eco
}
