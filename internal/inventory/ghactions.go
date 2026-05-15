package inventory

import (
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type ghWorkflow struct {
	Jobs map[string]ghJob `yaml:"jobs"`
}

type ghJob struct {
	Uses  string   `yaml:"uses"`
	Steps []ghStep `yaml:"steps"`
}

type ghStep struct {
	Uses string `yaml:"uses"`
}

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// parseGHActionsWorkflow walks a workflow YAML and collects every `uses:`
// reference into an inventory Package keyed by `owner/repo` and `ref`. Refs
// that are not 40-char SHAs are flagged as unpinned for later heuristics.
func parseGHActionsWorkflow(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wf ghWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, err
	}

	var out []Package
	seen := map[string]struct{}{}

	add := func(uses string) {
		if uses == "" || strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://") {
			return
		}
		at := strings.LastIndex(uses, "@")
		if at < 0 {
			return
		}
		name := uses[:at]
		ref := uses[at+1:]
		key := name + "@" + ref
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemActions,
			Name:       name,
			Version:    ref,
			PURL:       PURL(EcosystemActions, name, ref),
			SourcePath: path,
			Pinned:     shaRe.MatchString(ref),
		})
	}

	for _, job := range wf.Jobs {
		if job.Uses != "" {
			add(job.Uses)
		}
		for _, step := range job.Steps {
			add(step.Uses)
		}
	}
	return out, nil
}
