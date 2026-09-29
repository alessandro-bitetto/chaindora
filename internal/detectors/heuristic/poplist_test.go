package heuristic

import "testing"

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "abc", 0},
		{"", "abc", 3},
		{"abc", "", 3},
		{"lodash", "lodahs", 2},
		{"lodash", "lodas", 1},
		{"requests", "requets", 1},
		{"requests", "reqeusts", 2}, // adjacent transposition = 2 ops
		{"cross-env", "crossenv", 1},
		{"event-stream", "evenstream", 2},
	}
	for _, c := range cases {
		got := levenshtein(c.a, c.b)
		if got != c.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestIsInList(t *testing.T) {
	if !isInList("lodash", topNPM) {
		t.Error("expected lodash in topNPM")
	}
	if isInList("definitely-not-popular", topNPM) {
		t.Error("definitely-not-popular shouldn't be in topNPM")
	}
	if !isInList("requests", topPyPI) {
		t.Error("expected requests in topPyPI")
	}
}
