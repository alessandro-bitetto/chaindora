package inventory

import (
	"bufio"
	"bytes"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// parseDockerfile parses FROM directives in a Dockerfile and emits one
// Package per unique image reference. Handles `--platform=...` (and other)
// flags, optional `AS <name>` aliases, and skips `FROM scratch` plus any
// FROM line that interpolates a variable (which can't be resolved
// statically).
func parseDockerfile(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Package
	seen := map[string]struct{}{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(strings.ToUpper(line), "FROM ") {
			continue
		}
		rest := strings.TrimSpace(line[len("FROM "):])

		for strings.HasPrefix(rest, "--") {
			i := strings.IndexAny(rest, " \t")
			if i < 0 {
				rest = ""
				break
			}
			rest = strings.TrimSpace(rest[i+1:])
		}
		if i := strings.Index(strings.ToUpper(rest), " AS "); i >= 0 {
			rest = strings.TrimSpace(rest[:i])
		}
		if rest == "" || rest == "scratch" {
			continue
		}
		if strings.Contains(rest, "$") {
			continue
		}

		name, version, pinned := parseDockerImage(rest)
		if name == "" {
			continue
		}
		key := name + "@" + version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemDocker,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemDocker, name, version),
			SourcePath: path,
			Pinned:     pinned,
		})
	}
	return out, sc.Err()
}

// parseDockerImageRefs walks an arbitrary YAML document for every mapping
// key named "image" (case-insensitive) with a scalar string value. Used
// for CI YAMLs (GitLab/Bitbucket/CircleCI/GitHub Actions/Azure) and
// docker-compose files alike.
func parseDockerImageRefs(path string) ([]Package, error) {
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
	walkImageNodes(&root, func(imageRef string) {
		name, version, pinned := parseDockerImage(imageRef)
		if name == "" {
			return
		}
		key := name + "@" + version
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Ecosystem:  EcosystemDocker,
			Name:       name,
			Version:    version,
			PURL:       PURL(EcosystemDocker, name, version),
			SourcePath: path,
			Pinned:     pinned,
		})
	})
	return out, nil
}

func walkImageNodes(node *yaml.Node, emit func(string)) {
	if node == nil {
		return
	}
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range node.Content {
			walkImageNodes(c, emit)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			val := node.Content[i+1]
			if key.Kind == yaml.ScalarNode && val.Kind == yaml.ScalarNode &&
				strings.EqualFold(key.Value, "image") {
				emit(val.Value)
				continue
			}
			walkImageNodes(val, emit)
		}
	}
}

// parseDockerImage splits a docker image reference into (name, version, pinned).
//
//	nginx                           → "nginx",                          "",                  false
//	nginx:1.25                      → "nginx",                          "1.25",              false
//	library/nginx:1.25              → "library/nginx",                  "1.25",              false
//	gcr.io/proj/image:nonroot       → "gcr.io/proj/image",              "nonroot",           false
//	localhost:5000/img:v1           → "localhost:5000/img",             "v1",                false
//	nginx@sha256:abc...             → "nginx",                          "sha256:abc...",     true
func parseDockerImage(ref string) (name, version string, pinned bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return
	}
	if i := strings.Index(ref, "@sha256:"); i > 0 {
		return ref[:i], ref[i+1:], true
	}
	if i := strings.Index(ref, "@"); i > 0 {
		return ref[:i], ref[i+1:], false
	}
	// Last colon AFTER the last slash, to avoid splitting on a registry port
	// like "localhost:5000".
	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon > lastSlash && lastColon > 0 {
		return ref[:lastColon], ref[lastColon+1:], false
	}
	return ref, "", false
}
