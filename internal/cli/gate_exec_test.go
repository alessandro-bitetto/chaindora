package cli

import "testing"

func TestClassifyGateArgs(t *testing.T) {
	for _, args := range [][]string{{"ci"}, {"install"}, {"i"}, {"ci", "--ignore-scripts"}, {"clean-install"}} {
		if got := classifyGateArgs("npm", args); got != gateProceed {
			t.Errorf("refused frozen restore %v: %v", args, got)
		}
	}
	for pm := range pmClassifiers {
		for _, flag := range []string{"--version", "-v", "--help", "-h"} {
			if classifyGateArgs(pm, []string{flag}) != gatePassthrough {
				t.Errorf("%s %s", pm, flag)
			}
		}
		for _, args := range [][]string{nil, {"install", "example"}, {"pip", "install", "example"}, {"sync"}, {"restore"}, {"build"}, {"run", "build"}, {"test"}, {"update"}, {"--prefix=/tmp", "install"}, {"ci", "--ignore-scripts=false"}, {"ci", "--registry=http://localhost"}, {"exec", "example"}, {"unknown"}} {
			if got := classifyGateArgs(pm, args); got != gateRefuse {
				t.Errorf("ungated command %s %v: %v", pm, args, got)
			}
		}
		if pm != "npm" && classifyGateArgs(pm, []string{"install"}) != gateRefuse {
			t.Errorf("ungated restore %s", pm)
		}
	}
}
