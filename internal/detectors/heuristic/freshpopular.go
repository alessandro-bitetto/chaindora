package heuristic

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
	"github.com/alessandro-bitetto/chaindora/internal/inventory"
)

// FreshPopularConfig controls the fresh-popular detector. Empty config keeps
// the detector disabled; toggling Enabled on causes one HTTP call per top-N
// inventory package to the relevant public registry.
type FreshPopularConfig struct {
	Enabled         bool
	NPMRegistryURL  string
	PyPIRegistryURL string
	HTTPClient      *http.Client
	Now             func() time.Time
}

const (
	defaultNPMRegistryURL  = "https://registry.npmjs.org"
	defaultPyPIRegistryURL = "https://pypi.org/pypi"
	freshWindow            = 14 * 24 * time.Hour
)

// detectFreshPopular flags inventory packages that match a top-N popular
// name AND whose locked version was published less than freshWindow ago.
// Maintainer-account compromise has historically been the vector for
// short-lived malicious releases of established packages (ua-parser-js 2021,
// chalk/debug Sept 2025, …).
func detectFreshPopular(inv *inventory.Inventory, cfg FreshPopularConfig) []findings.Finding {
	if !cfg.Enabled || inv == nil {
		return nil
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	npmURL := cfg.NPMRegistryURL
	if npmURL == "" {
		npmURL = defaultNPMRegistryURL
	}
	pypiURL := cfg.PyPIRegistryURL
	if pypiURL == "" {
		pypiURL = defaultPyPIRegistryURL
	}

	cache := map[string]time.Time{}
	var out []findings.Finding
	for i := range inv.Packages {
		p := &inv.Packages[i]
		var pool []string
		switch p.Ecosystem {
		case inventory.EcosystemNPM:
			pool = topNPM
		case inventory.EcosystemPyPI:
			pool = topPyPI
		default:
			continue
		}
		if !isInList(p.Name, pool) {
			continue
		}
		published, err := fetchPublishDate(client, p, npmURL, pypiURL, cache)
		if err != nil {
			continue
		}
		age := now().Sub(published)
		if age > freshWindow || age < 0 {
			continue
		}
		out = append(out, findings.Finding{
			Detector:  "heuristic:fresh-popular",
			PURL:      p.PURL,
			Ecosystem: p.Ecosystem,
			Name:      p.Name,
			Version:   p.Version,
			VulnID:    "HEUR-FRESH-POPULAR",
			Summary: fmt.Sprintf(
				"Popular package %s@%s was published %d day(s) ago. Maintainer-account compromise has historically led to short-lived malicious releases of established packages — verify the release before trusting it.",
				p.Name, p.Version, int(age.Hours()/24),
			),
			Severity:   findings.SeverityHigh,
			SourcePath: p.SourcePath,
		})
	}
	return out
}

func fetchPublishDate(client *http.Client, p *inventory.Package, npmURL, pypiURL string, cache map[string]time.Time) (time.Time, error) {
	key := string(p.Ecosystem) + "|" + p.Name + "|" + p.Version
	if t, ok := cache[key]; ok {
		return t, nil
	}
	var when time.Time
	var err error
	switch p.Ecosystem {
	case inventory.EcosystemNPM:
		when, err = fetchNPMPublishDate(client, npmURL, p.Name, p.Version)
	case inventory.EcosystemPyPI:
		when, err = fetchPyPIPublishDate(client, pypiURL, p.Name, p.Version)
	default:
		return time.Time{}, fmt.Errorf("unsupported ecosystem %q", p.Ecosystem)
	}
	if err == nil {
		cache[key] = when
	}
	return when, err
}

func fetchNPMPublishDate(client *http.Client, base, name, version string) (time.Time, error) {
	resp, err := client.Get(base + "/" + name)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("npm %s: status %d", name, resp.StatusCode)
	}
	var doc struct {
		Time map[string]string `json:"time"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return time.Time{}, err
	}
	s, ok := doc.Time[version]
	if !ok {
		return time.Time{}, fmt.Errorf("npm %s: no time for version %s", name, version)
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("npm %s: parse time: %w", name, err)
	}
	return t, nil
}

func fetchPyPIPublishDate(client *http.Client, base, name, version string) (time.Time, error) {
	resp, err := client.Get(base + "/" + name + "/" + version + "/json")
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("pypi %s/%s: status %d", name, version, resp.StatusCode)
	}
	var doc struct {
		Urls []struct {
			UploadTime string `json:"upload_time"`
		} `json:"urls"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return time.Time{}, err
	}
	if len(doc.Urls) == 0 {
		return time.Time{}, fmt.Errorf("pypi %s/%s: no urls", name, version)
	}
	t, err := time.Parse("2006-01-02T15:04:05", doc.Urls[0].UploadTime)
	if err != nil {
		return time.Time{}, fmt.Errorf("pypi %s/%s: parse time: %w", name, version, err)
	}
	return t, nil
}
