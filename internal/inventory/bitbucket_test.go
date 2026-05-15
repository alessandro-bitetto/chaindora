package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseBitbucketPipelines(t *testing.T) {
	content := `image: node:20

pipelines:
  default:
    - step:
        name: Build
        script:
          - npm ci
    - step:
        name: Deploy
        script:
          - pipe: atlassian/aws-s3-deploy:1.1.0
          - pipe: atlassian/slack-notify:2.0.1
  branches:
    main:
      - step:
          script:
            - pipe: atlassian/aws-s3-deploy:1.1.0  # dup, should dedupe
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bitbucket-pipelines.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseBitbucketPipelines(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"atlassian/aws-s3-deploy": "1.1.0",
		"atlassian/slack-notify":  "2.0.1",
	}
	if len(pkgs) != len(want) {
		t.Fatalf("got %d, want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for _, p := range pkgs {
		w, ok := want[p.Name]
		if !ok || p.Version != w {
			t.Errorf("unexpected %s@%s; want %v", p.Name, p.Version, want)
		}
		if p.Ecosystem != EcosystemBitbucketPipes {
			t.Errorf("wrong ecosystem: %q", p.Ecosystem)
		}
	}
}
