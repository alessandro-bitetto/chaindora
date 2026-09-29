package incidents

import (
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Incident is the on-disk YAML descriptor for a single supply-chain incident.
type Incident struct {
	Schema         int               `yaml:"schema"`
	ID             string            `yaml:"id"`
	Name           string            `yaml:"name"`
	Severity       string            `yaml:"severity"`
	Date           string            `yaml:"date"`
	Summary        string            `yaml:"summary"`
	References     []string          `yaml:"references"`
	Packages       []IncidentPackage `yaml:"packages"`
	FileArtifacts  []FileArtifact    `yaml:"file_artifacts"`
	PostCompromise []string          `yaml:"post_compromise,omitempty"`
}

type IncidentPackage struct {
	Ecosystem   string   `yaml:"ecosystem"`
	Name        string   `yaml:"name"`
	Versions    []string `yaml:"versions"`
	SafeVersion string   `yaml:"safe_version,omitempty"`
}

type FileArtifact struct {
	Glob          string `yaml:"glob"`
	Severity      string `yaml:"severity"`
	Description   string `yaml:"description"`
	ContentSubstr string `yaml:"content_substr,omitempty"`
}

// LoadDir parses every *.yaml / *.yml file under dir into an Incident.
// Returns the incidents sorted by ID for stable output.
func LoadDir(dir string) ([]*Incident, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*Incident
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var inc Incident
		if err := yaml.Unmarshal(data, &inc); err != nil {
			return nil, err
		}
		if inc.ID == "" {
			continue
		}
		out = append(out, &inc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ResolveDir returns the first candidate path that exists and is a directory,
// or empty string if none do. Empty candidates are skipped.
func ResolveDir(candidates []string) string {
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return ""
}
