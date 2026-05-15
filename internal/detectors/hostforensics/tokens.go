package hostforensics

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

type tokenCheck struct {
	Path     string
	Patterns []*regexp.Regexp
	VulnID   string
	Summary  string
}

var tokenChecks = []tokenCheck{
	{
		Path: ".npmrc",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?m)^[^#\n]*_authToken\s*=\s*\S+`),
			regexp.MustCompile(`(?m)^[^#\n]*_password\s*=\s*\S+`),
			regexp.MustCompile(`(?m)^[^#\n]*_auth\s*=\s*\S+`),
		},
		VulnID:  "HOST-NPM-TOKEN-PRESENT",
		Summary: "An npm registry credential is stored in ~/.npmrc. If a recent npm package compromise affected your dependencies, rotate this token immediately.",
	},
	{
		Path: ".pypirc",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?m)^[^#\n]*password\s*=\s*\S+`),
			regexp.MustCompile(`pypi-AgEI`),
		},
		VulnID:  "HOST-PYPI-TOKEN-PRESENT",
		Summary: "A PyPI credential is stored in ~/.pypirc. Rotate if a recent PyPI compromise may have exfiltrated it.",
	},
	{
		Path: ".docker/config.json",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`"auths"\s*:\s*\{[^}]*"auth"`),
		},
		VulnID:  "HOST-DOCKER-AUTH-PRESENT",
		Summary: "Docker registry credentials are stored in ~/.docker/config.json. Rotate if compromise suspected.",
	},
	{
		Path: ".aws/credentials",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?m)^[^#\n]*aws_secret_access_key\s*=\s*\S+`),
		},
		VulnID:  "HOST-AWS-SECRET-PRESENT",
		Summary: "AWS credentials are stored in ~/.aws/credentials. Rotate if compromise suspected.",
	},
	{
		Path: ".gem/credentials",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`rubygems_api_key`),
		},
		VulnID:  "HOST-RUBYGEMS-TOKEN-PRESENT",
		Summary: "A RubyGems API key is stored in ~/.gem/credentials. Rotate if compromise suspected.",
	},
	{
		Path: ".cargo/credentials.toml",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?m)^[^#\n]*token\s*=\s*"\S+"`),
		},
		VulnID:  "HOST-CRATES-TOKEN-PRESENT",
		Summary: "A crates.io token is stored in ~/.cargo/credentials.toml. Rotate if compromise suspected.",
	},
}

func scanTokens(home string) []findings.Finding {
	var out []findings.Finding
	for _, c := range tokenChecks {
		full := filepath.Join(home, c.Path)
		data, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		text := string(data)
		if strings.TrimSpace(text) == "" {
			continue
		}
		for _, re := range c.Patterns {
			if re.MatchString(text) {
				out = append(out, findings.Finding{
					Detector:   "hostforensics:tokens",
					VulnID:     c.VulnID,
					Summary:    c.Summary,
					Severity:   findings.SeverityMedium,
					SourcePath: full,
				})
				break
			}
		}
	}
	return out
}
