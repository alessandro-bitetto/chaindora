package cli

import (
	"errors"
	"fmt"
	"testing"
)

func TestExitError_ErrorString(t *testing.T) {
	cases := []struct {
		name string
		e    *ExitError
		want string
	}{
		{"with-wrapped-err", &ExitError{Code: 3, Err: errors.New("kaboom")}, "kaboom"},
		{"bare-code", &ExitError{Code: 1}, "exit 1"},
		{"nil-receiver", nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.e.Error(); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestExitError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	e := &ExitError{Code: 5, Err: inner}
	if got := e.Unwrap(); got != inner {
		t.Errorf("Unwrap: got %v, want %v", got, inner)
	}
	var nilExit *ExitError
	if got := nilExit.Unwrap(); got != nil {
		t.Errorf("nil receiver Unwrap should return nil, got %v", got)
	}
}

func TestExitError_ErrorsIs(t *testing.T) {
	// ExitError must Unwrap to the inner err so errors.Is works
	// through the chain.
	sentinel := errors.New("sentinel")
	wrapped := fmt.Errorf("context: %w", sentinel)
	e := &ExitError{Code: 1, Err: wrapped}
	if !errors.Is(e, sentinel) {
		t.Error("errors.Is must traverse ExitError → wrapped → sentinel")
	}
}

func TestExitError_ErrorsAs(t *testing.T) {
	// Callers (and root.Execute) extract the ExitError via errors.As
	// on a possibly-wrapped error.
	e := &ExitError{Code: 7}
	wrapped := fmt.Errorf("outer: %w", e)
	var got *ExitError
	if !errors.As(wrapped, &got) {
		t.Fatal("errors.As must find ExitError through wrapping")
	}
	if got.Code != 7 {
		t.Errorf("recovered code: got %d, want 7", got.Code)
	}
}

func TestSilentExit_ProducesExitError(t *testing.T) {
	err := SilentExit(42)
	var got *ExitError
	if !errors.As(err, &got) {
		t.Fatal("SilentExit must produce ExitError")
	}
	if got.Code != 42 {
		t.Errorf("code: got %d, want 42", got.Code)
	}
	if got.Err != nil {
		t.Errorf("SilentExit should not carry a message, got %v", got.Err)
	}
	if got.Error() != "exit 42" {
		t.Errorf("Error() string: got %q, want %q", got.Error(), "exit 42")
	}
}
