package inventory

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// parseAzurePipelines walks an Azure DevOps pipelines YAML for every
// `task: Name@MajorVersion` reference at any depth. Templates from external
// repos (`template: file.yml@<repo-alias>`) are NOT inventoried here in v0 —
// resolving the alias to `resources.repositories[]` is left for a follow-up.
func parseAzurePipelines(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	var out []Package
	seen := map[string]struct{}{}
	walkAzureTasks(&root, func(taskRef string) {
		i := strings.LastIndex(taskRef, "@")
		if i <= 0 {
			return
		}
		name := taskRef[:i]
		version := taskRef[i+1:]
		key := name + "@" + version
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemAzurePipelines,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemAzurePipelines, name, version),
			SourcePath: path,
		})
	})
	return out, nil
}

func walkAzureTasks(node *yaml.Node, emit func(string)) {
	if node == nil {
		return
	}
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range node.Content {
			walkAzureTasks(c, emit)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			val := node.Content[i+1]
			if key.Kind == yaml.ScalarNode && val.Kind == yaml.ScalarNode && strings.EqualFold(key.Value, "task") {
				emit(val.Value)
				continue
			}
			walkAzureTasks(val, emit)
		}
	}
}
