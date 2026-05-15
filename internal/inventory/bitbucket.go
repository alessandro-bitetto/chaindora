package inventory

import (
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// pipeRe matches a Bitbucket pipe reference: "namespace/tool:version".
var pipeRe = regexp.MustCompile(`^([\w.\-]+)/([\w.\-]+):([\w.\-]+)$`)

// parseBitbucketPipelines walks a `bitbucket-pipelines.yml` for every
// `pipe: ns/tool:version` reference at any depth. `image:` and `services:`
// are inventoried by the Docker scanner in P3b.
func parseBitbucketPipelines(path string) ([]Package, error) {
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
	walkPipeNode(&root, func(pipe string) {
		m := pipeRe.FindStringSubmatch(pipe)
		if m == nil {
			return
		}
		name := m[1] + "/" + m[2]
		version := m[3]
		key := name + "@" + version
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemBitbucketPipes,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemBitbucketPipes, name, version),
			SourcePath: path,
		})
	})
	return out, nil
}

// walkPipeNode finds every mapping key "pipe" with a scalar string value.
func walkPipeNode(node *yaml.Node, emit func(pipe string)) {
	if node == nil {
		return
	}
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range node.Content {
			walkPipeNode(c, emit)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			val := node.Content[i+1]
			if key.Kind == yaml.ScalarNode && val.Kind == yaml.ScalarNode && strings.EqualFold(key.Value, "pipe") {
				emit(val.Value)
				continue
			}
			walkPipeNode(val, emit)
		}
	}
}
