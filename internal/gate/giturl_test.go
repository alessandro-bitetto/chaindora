package gate

import (
	"context"
	"testing"
)

func TestGitURL_ApprovesGitHubPinnedSHA(t *testing.T) {
	g := NewGitURLCheck()
	r := g.Check(context.Background(), PackageRef{
		Ecosystem: "git",
		Name:      "myrepo",
		Version:   "https://github.com/user/repo#a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
	})
	if r.Verdict != VerdictApprove {
		t.Errorf("github + 40-hex SHA should Approve, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestGitURL_BlocksGitHubBranch(t *testing.T) {
	g := NewGitURLCheck()
	r := g.Check(context.Background(), PackageRef{
		Ecosystem: "git",
		Name:      "x",
		Version:   "https://github.com/user/repo#main",
	})
	if r.Verdict != VerdictBlock {
		t.Errorf("github + main branch should Block, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestGitURL_WarnsOnGitHubTag(t *testing.T) {
	g := NewGitURLCheck()
	r := g.Check(context.Background(), PackageRef{
		Ecosystem: "git",
		Name:      "x",
		Version:   "https://github.com/user/repo#v1.2.3",
	})
	if r.Verdict != VerdictWarn {
		t.Errorf("github + version tag should Warn (mutable), got %v: %q", r.Verdict, r.Reason)
	}
}

func TestGitURL_BlocksHTTPScheme(t *testing.T) {
	g := NewGitURLCheck()
	r := g.Check(context.Background(), PackageRef{
		Ecosystem: "git",
		Name:      "x",
		Version:   "http://github.com/user/repo#abc1234",
	})
	if r.Verdict != VerdictBlock {
		t.Errorf("http:// should Block (no transport security), got %v: %q", r.Verdict, r.Reason)
	}
}

func TestGitURL_BlocksGitScheme(t *testing.T) {
	g := NewGitURLCheck()
	r := g.Check(context.Background(), PackageRef{
		Ecosystem: "git",
		Name:      "x",
		Version:   "git://github.com/user/repo#abc1234",
	})
	if r.Verdict != VerdictBlock {
		t.Errorf("git:// should Block, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestGitURL_BlocksUnknownHostWithTag(t *testing.T) {
	g := NewGitURLCheck()
	r := g.Check(context.Background(), PackageRef{
		Ecosystem: "git",
		Name:      "x",
		Version:   "https://random-host.example.com/user/repo#v1.0",
	})
	if r.Verdict != VerdictBlock {
		t.Errorf("unknown host + tag should Block, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestGitURL_WarnsOnUnknownHostWithSHA(t *testing.T) {
	g := NewGitURLCheck()
	r := g.Check(context.Background(), PackageRef{
		Ecosystem: "git",
		Name:      "x",
		Version:   "https://random-host.example.com/user/repo#a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
	})
	if r.Verdict != VerdictWarn {
		t.Errorf("unknown host + SHA should Warn (auditable bytes), got %v: %q", r.Verdict, r.Reason)
	}
}

func TestGitURL_AllowlistedHostApprovesWithSHA(t *testing.T) {
	g := &GitURLCheck{AllowedHosts: []string{"corp-git.internal"}}
	r := g.Check(context.Background(), PackageRef{
		Ecosystem: "git",
		Name:      "x",
		Version:   "https://corp-git.internal/team/repo#a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
	})
	if r.Verdict != VerdictApprove {
		t.Errorf("allowlisted host + SHA should Approve, got %v: %q", r.Verdict, r.Reason)
	}
}

func TestGitURL_AllowBranchRefsDowngradesToWarn(t *testing.T) {
	g := &GitURLCheck{AllowBranchRefs: true}
	r := g.Check(context.Background(), PackageRef{
		Ecosystem: "git",
		Name:      "x",
		Version:   "https://github.com/user/repo#main",
	})
	if r.Verdict != VerdictWarn {
		t.Errorf("AllowBranchRefs=true should Warn (not Block), got %v: %q", r.Verdict, r.Reason)
	}
}

func TestGitURL_NonGitEcosystemPassthrough(t *testing.T) {
	g := NewGitURLCheck()
	r := g.Check(context.Background(), PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})
	if r.Verdict != VerdictApprove {
		t.Errorf("non-git ecosystem should Approve passthrough, got %v", r.Verdict)
	}
}

func TestClassifyRef(t *testing.T) {
	cases := map[string]refKind{
		"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0": refSHA,    // 40-hex
		"a1b2c3d":                                  refSHA,    // 7-hex short
		"abcd1234":                                 refSHA,    // 8-hex
		"main":                                     refBranch,
		"master":                                   refBranch,
		"develop":                                  refBranch,
		"v1.2.3":                                   refTag,
		"v0.5-beta":                                refTag,
		"1.2.3":                                    refTag,
		"some-feature-branch":                      refBranch,
		"":                                         refBranch, // empty falls to default branch
	}
	for in, want := range cases {
		if got := classifyRef(in); got != want {
			t.Errorf("classifyRef(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseGitURLSpec(t *testing.T) {
	spec, ok := parseGitURLSpec("foo", "git+https://github.com/user/repo.git#abc1234")
	if !ok {
		t.Fatal("expected parse success for git+https")
	}
	if spec.Host != "github.com" || spec.Ref != "abc1234" {
		t.Errorf("parsed: %+v", spec)
	}

	if _, ok := parseGitURLSpec("foo", "github.com/user/repo"); ok {
		t.Error("expected failure on URL without ref")
	}
}
