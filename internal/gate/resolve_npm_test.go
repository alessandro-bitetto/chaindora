package gate

import (
	"testing"
)

func TestParseNPMLockTree_FlattensTree(t *testing.T) {
	lock := []byte(`{
  "name": "test", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": { "name": "test", "version": "1.0.0", "dependencies": { "lodash": "^4.17.21" } },
    "node_modules/lodash": { "version": "4.17.21" },
    "node_modules/foo": { "version": "1.2.3" },
    "node_modules/foo/node_modules/lodash": { "version": "3.10.1" }
  }
}`)
	refs, err := parseNPMLockTree(lock, []string{"lodash@^4.17.21"})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 3 {
		t.Errorf("expected 3 refs (lodash@4.17.21, foo@1.2.3, lodash@3.10.1), got %d: %v", len(refs), refs)
	}
	// Build a lookup so order-independent.
	byID := map[string]PackageRef{}
	for _, r := range refs {
		byID[r.String()] = r
	}
	if _, ok := byID["npm:lodash@4.17.21"]; !ok {
		t.Errorf("missing lodash@4.17.21: %v", refs)
	}
	if _, ok := byID["npm:lodash@3.10.1"]; !ok {
		t.Errorf("missing nested lodash@3.10.1: %v", refs)
	}
	if !byID["npm:lodash@4.17.21"].Direct {
		t.Errorf("lodash should be marked Direct (user asked for it)")
	}
	if byID["npm:foo@1.2.3"].Direct {
		t.Errorf("foo should be Direct=false (transitive)")
	}
}

func TestStripNodeModulesPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"node_modules/lodash", "lodash"},
		{"node_modules/@scope/pkg", "@scope/pkg"},
		{"node_modules/foo/node_modules/bar", "bar"},
		{"node_modules/foo/node_modules/@s/b", "@s/b"},
	}
	for _, c := range cases {
		if got := stripNodeModulesPath(c.in); got != c.want {
			t.Errorf("stripNodeModulesPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDirectNamesFromArgs(t *testing.T) {
	cases := []struct {
		args []string
		want map[string]bool
	}{
		{[]string{"lodash"}, map[string]bool{"lodash": true}},
		{[]string{"lodash@4.17.21"}, map[string]bool{"lodash": true}},
		{[]string{"@scope/pkg@1.0"}, map[string]bool{"@scope/pkg": true}},
		{[]string{"@scope/pkg"}, map[string]bool{"@scope/pkg": true}},
		{[]string{"--save-dev", "lodash@4.17.21", "react@18"}, map[string]bool{"lodash": true, "react": true}},
	}
	for _, c := range cases {
		got := directNamesFromArgs(c.args)
		if len(got) != len(c.want) {
			t.Errorf("directNamesFromArgs(%v): got %v, want %v", c.args, got, c.want)
			continue
		}
		for k := range c.want {
			if !got[k] {
				t.Errorf("directNamesFromArgs(%v) missing %q: %v", c.args, k, got)
			}
		}
	}
}

func TestParseNPMLockTree_DedupesIdenticalEntries(t *testing.T) {
	lock := []byte(`{
  "packages": {
    "": { "name": "test", "version": "1.0.0" },
    "node_modules/lodash": { "version": "4.17.21" },
    "node_modules/foo/node_modules/lodash": { "version": "4.17.21" }
  }
}`)
	refs, err := parseNPMLockTree(lock, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 {
		t.Errorf("identical (name, version) at two depths should dedupe to 1, got %d: %v", len(refs), refs)
	}
}
