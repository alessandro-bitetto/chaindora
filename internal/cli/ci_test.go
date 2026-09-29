package cli

import (
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

func TestDetectCI(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"none", map[string]string{}, ""},
		{"github actions", map[string]string{"GITHUB_ACTIONS": "true"}, "github-actions"},
		{"gitlab ci", map[string]string{"GITLAB_CI": "true"}, "gitlab-ci"},
		{"circleci", map[string]string{"CIRCLECI": "true"}, "circleci"},
		{"bitbucket", map[string]string{"BITBUCKET_BUILD_NUMBER": "42"}, "bitbucket"},
		{"azure pipelines", map[string]string{"TF_BUILD": "True"}, "azure-pipelines"},
		{"drone", map[string]string{"DRONE": "true"}, "drone"},
		{"jenkins via JENKINS_HOME", map[string]string{"JENKINS_HOME": "/var/jenkins"}, "jenkins"},
		{"jenkins via BUILD_TAG", map[string]string{"BUILD_TAG": "jenkins-job-1"}, "jenkins"},
		{"github wins over noise", map[string]string{"GITHUB_ACTIONS": "true", "JENKINS_HOME": "/x"}, "github-actions"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			getenv := func(k string) string { return c.env[k] }
			if got := detectCI(getenv); got != c.want {
				t.Errorf("detectCI = %q, want %q", got, c.want)
			}
		})
	}
}

func TestFormatForCI(t *testing.T) {
	if got := formatForCI("github-actions"); got != "github" {
		t.Errorf("github-actions → %q, want \"github\"", got)
	}
	if got := formatForCI(""); got != "text" {
		t.Errorf("unknown → %q, want \"text\"", got)
	}
	if got := formatForCI("gitlab-ci"); got != "text" {
		t.Errorf("gitlab-ci → %q, want \"text\"", got)
	}
}

func TestShouldFail(t *testing.T) {
	crit := findings.Finding{Severity: findings.SeverityCritical}
	high := findings.Finding{Severity: findings.SeverityHigh}
	med := findings.Finding{Severity: findings.SeverityMedium}
	low := findings.Finding{Severity: findings.SeverityLow}
	unk := findings.Finding{Severity: findings.SeverityUnknown}

	cases := []struct {
		name      string
		threshold string
		fs        []findings.Finding
		want      bool
	}{
		{"default catches critical", "critical,high", []findings.Finding{crit}, true},
		{"default catches high", "critical,high", []findings.Finding{high}, true},
		{"default skips medium", "critical,high", []findings.Finding{med}, false},
		{"default skips unknown", "critical,high", []findings.Finding{unk}, false},
		{"critical-only ignores high", "critical", []findings.Finding{high, med}, false},
		{"any catches medium", "any", []findings.Finding{med}, true},
		{"any catches low", "any", []findings.Finding{low}, true},
		{"any rejects empty", "any", nil, false},
		{"none always passes", "none", []findings.Finding{crit, high, med}, false},
		{"empty == none", "", []findings.Finding{crit}, false},
		{"case insensitive threshold", "CRITICAL", []findings.Finding{crit}, true},
		{"trims whitespace", " critical , high ", []findings.Finding{high}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldFail(c.fs, c.threshold); got != c.want {
				t.Errorf("shouldFail = %v, want %v", got, c.want)
			}
		})
	}
}
