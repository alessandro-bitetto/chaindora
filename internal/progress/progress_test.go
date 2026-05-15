package progress

import (
	"bytes"
	"testing"
)

func TestFormatCount(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0"},
		{42, "42"},
		{999, "999"},
		{1000, "1,000"},
		{12345, "12,345"},
		{1234567, "1,234,567"},
		{1000000000, "1,000,000,000"},
	}
	for _, c := range cases {
		if got := formatCount(c.n); got != c.want {
			t.Errorf("formatCount(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestNonTTYIsNoOp(t *testing.T) {
	// bytes.Buffer is not an *os.File, so isTerminal returns false and
	// every method is a no-op. Verify nothing gets written.
	var buf bytes.Buffer
	r := New(&buf)
	r.Start("hunting")
	for i := 0; i < 100; i++ {
		r.Tick()
	}
	r.Hit()
	r.SetLabel("scanning")
	r.Stop("done")
	if buf.Len() != 0 {
		t.Errorf("non-TTY reporter wrote %d bytes, want 0: %q", buf.Len(), buf.String())
	}
}
