package gate

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"testing"
)

func TestWrapPMError_NilErrReturnsNil(t *testing.T) {
	if got := wrapPMError("npm", "install foo", nil, nil); got != nil {
		t.Errorf("nil err must produce nil, got %v", got)
	}
}

func TestWrapPMError_ExitErrorBecomesPMError(t *testing.T) {
	// Synthesize a real *exec.ExitError by running a guaranteed-fail command.
	var exitCmd string
	var exitArgs []string
	if runtime.GOOS == "windows" {
		exitCmd = "cmd"
		exitArgs = []string{"/c", "exit 7"}
	} else {
		exitCmd = "sh"
		exitArgs = []string{"-c", "exit 7"}
	}
	cmd := exec.Command(exitCmd, exitArgs...)
	runErr := cmd.Run()
	if runErr == nil {
		t.Fatal("expected non-zero exit")
	}

	wrapped := wrapPMError("npm", "install lodash", []byte("npm ERR! foo\n"), runErr)
	var pmErr *PMError
	if !errors.As(wrapped, &pmErr) {
		t.Fatalf("expected *PMError, got %T: %v", wrapped, wrapped)
	}
	if pmErr.PM != "npm" || pmErr.Command != "install lodash" {
		t.Errorf("PMError fields wrong: %+v", pmErr)
	}
	if pmErr.ExitCode != 7 {
		t.Errorf("ExitCode: got %d, want 7", pmErr.ExitCode)
	}
	if string(pmErr.Output) != "npm ERR! foo\n" {
		t.Errorf("Output: got %q, want %q", string(pmErr.Output), "npm ERR! foo\n")
	}
}

func TestWrapPMError_NonExitErrorWraps(t *testing.T) {
	// A non-ExitError (e.g. binary-not-found) should NOT become a
	// PMError — it's a chdora-internal failure, not a PM diagnostic.
	startErr := fmt.Errorf("exec: not found")
	wrapped := wrapPMError("npm", "install foo", nil, startErr)
	var pmErr *PMError
	if errors.As(wrapped, &pmErr) {
		t.Errorf("non-ExitError must not become PMError, got %T", wrapped)
	}
	if wrapped == nil || wrapped.Error() == "" {
		t.Errorf("wrapped err must be non-nil with message; got %v", wrapped)
	}
	// And the original error must be unwrappable.
	if !errors.Is(wrapped, startErr) {
		t.Errorf("wrapped err must Unwrap to original; got chain: %v", wrapped)
	}
}

func TestPMError_Error_PrefersOutput(t *testing.T) {
	e := &PMError{PM: "npm", Command: "install foo", ExitCode: 1, Output: []byte("npm ERR! 404 not found\n")}
	if got := e.Error(); got != "npm ERR! 404 not found\n" {
		t.Errorf("Error() should return Output verbatim when present; got %q", got)
	}
}

func TestPMError_Error_FallsBackToSummary(t *testing.T) {
	e := &PMError{PM: "npm", Command: "install foo", ExitCode: 2}
	got := e.Error()
	if got == "" {
		t.Error("empty fallback summary")
	}
	if got == "npm install foo: exit 2" {
		// Good.
	} else {
		t.Errorf("unexpected summary: %q", got)
	}
}

func TestPMError_Unwrap(t *testing.T) {
	inner := fmt.Errorf("inner")
	e := &PMError{Err: inner}
	if got := e.Unwrap(); got != inner {
		t.Errorf("Unwrap got %v, want %v", got, inner)
	}
}
