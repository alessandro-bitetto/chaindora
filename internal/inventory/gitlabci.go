package inventory

import (
	"os"

	"gopkg.in/yaml.v3"
)

// parseGitLabCI parses a `.gitlab-ci.yml`. Captures `include:` entries:
//   - project: <owner/repo>, ref: <ref>, file: <path>  → Package(project, ref)
//   - template: <Name>                                  → Package("template:<Name>")
//   - remote: <URL>                                     → Package("remote:<URL>")
//
// Local `include:` entries are skipped (same-repo files, no supply-chain
// risk). `image:` and `services:` are intentionally NOT inventoried here —
// they're picked up by the Docker scanner in P3b.
func parseGitLabCI(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root struct {
		Include yaml.Node `yaml:"include"`
	}
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	var out []Package
	seen := map[string]struct{}{}
	emit := func(name, version string) {
		if name == "" {
			return
		}
		key := name + "@" + version
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemGitLabCI,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemGitLabCI, name, version),
			SourcePath: path,
			Pinned:     shaRe.MatchString(version),
		})
	}
	walkGitLabInclude(&root.Include, emit)
	return out, nil
}

type gitlabInclude struct {
	Project  string `yaml:"project"`
	File     string `yaml:"file"`
	Ref      string `yaml:"ref"`
	Template string `yaml:"template"`
	Remote   string `yaml:"remote"`
}

func walkGitLabInclude(node *yaml.Node, emit func(name, version string)) {
	if node == nil || node.Kind == 0 {
		return
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, c := range node.Content {
			walkGitLabInclude(c, emit)
		}
	case yaml.SequenceNode:
		for _, c := range node.Content {
			walkGitLabInclude(c, emit)
		}
	case yaml.MappingNode:
		var inc gitlabInclude
		_ = node.Decode(&inc)
		switch {
		case inc.Project != "":
			emit(inc.Project, inc.Ref)
		case inc.Template != "":
			emit("template:"+inc.Template, "")
		case inc.Remote != "":
			emit("remote:"+inc.Remote, "")
		}
	}
}
