package gate

import (
	"bytes"
	"context"
	"io"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/registries"
)

// stubProbe is the universal test fixture for the new
// Probes-based API. Tests parameterize its fields per case.
type stubProbe struct {
	publishedAtByVersion map[string]time.Time
	publisherByVersion   map[string]string
	versions             []registries.VersionInfo
	tarballURL           string
	tarballContents      []byte

	publishedAtErr error
	publisherErr   error
	versionsErr    error
	tarballURLErr  error
	fetchErr       error
}

func (s stubProbe) PublishedAtVersion(_ context.Context, _, version string) (time.Time, error) {
	if s.publishedAtErr != nil {
		return time.Time{}, s.publishedAtErr
	}
	return s.publishedAtByVersion[version], nil
}

func (s stubProbe) PublisherOfVersion(_ context.Context, _, version string) (string, error) {
	if s.publisherErr != nil {
		return "", s.publisherErr
	}
	return s.publisherByVersion[version], nil
}

func (s stubProbe) AllVersions(_ context.Context, _ string) ([]registries.VersionInfo, error) {
	return s.versions, s.versionsErr
}

func (s stubProbe) TarballURL(_ context.Context, _, _ string) (string, error) {
	return s.tarballURL, s.tarballURLErr
}

func (s stubProbe) FetchTarball(_ context.Context, _ string, dst io.Writer) error {
	if s.fetchErr != nil {
		return s.fetchErr
	}
	_, err := dst.Write(s.tarballContents)
	return err
}

// probesWith wires a single ecosystem's stub probe and returns a
// ready-to-use Probes. Quality-of-life helper for short tests.
func probesWith(ecosystem string, probe VersionProbe) *Probes {
	p := NewProbes()
	p.Register(ecosystem, probe)
	return p
}

// Compile-time check that stubProbe implements VersionProbe.
var _ VersionProbe = stubProbe{}

// Make sure the unused-imports check stays happy in this file.
var _ = bytes.Buffer{}
