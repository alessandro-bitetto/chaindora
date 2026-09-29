package hostforensics

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanTokensMultipleFiles(t *testing.T) {
	home := t.TempDir()

	mustWrite(t, filepath.Join(home, ".npmrc"), `//registry.npmjs.org/:_authToken=npm_FAKE_TOKEN_xxxxxxxxxxxxxxxxxxxxxxxx
registry=https://registry.npmjs.org/
`)
	mustWrite(t, filepath.Join(home, ".pypirc"), `[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmcCJFAKEFAKEFAKE
`)
	if err := os.Mkdir(filepath.Join(home, ".aws"), 0700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(home, ".aws", "credentials"), `[default]
aws_access_key_id = AKIAFAKE
aws_secret_access_key = FAKESECRET1234567890
`)

	got := scanTokens(home)
	gotIDs := map[string]bool{}
	for _, f := range got {
		gotIDs[f.VulnID] = true
	}
	for _, want := range []string{
		"HOST-NPM-TOKEN-PRESENT",
		"HOST-PYPI-TOKEN-PRESENT",
		"HOST-AWS-SECRET-PRESENT",
	} {
		if !gotIDs[want] {
			t.Errorf("missing finding %s; got %v", want, gotIDs)
		}
	}
}

func TestScanTokensSkipsComments(t *testing.T) {
	home := t.TempDir()
	mustWrite(t, filepath.Join(home, ".npmrc"), `# //registry.npmjs.org/:_authToken=commented-out-token
registry=https://registry.npmjs.org/
`)
	if got := scanTokens(home); len(got) != 0 {
		t.Errorf("expected 0 findings for commented-out token, got %d: %+v", len(got), got)
	}
}

func TestScanTokensEmpty(t *testing.T) {
	home := t.TempDir()
	if got := scanTokens(home); len(got) != 0 {
		t.Errorf("expected 0 findings on empty home, got %d", len(got))
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
