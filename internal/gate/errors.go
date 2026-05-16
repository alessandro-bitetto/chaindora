package gate

import (
	"errors"
	"fmt"
	"os/exec"
)

// PMError is returned by a resolver when the underlying package
// manager exited non-zero. It carries the PM's own diagnostic
// output verbatim so the CLI can reproduce it for the user instead
// of wrapping it in a chdora-prefixed error.
//
// Why distinguish this from a generic error: if `npm install foo`
// would have failed regardless of chdora (typo, 404, peer-dep
// conflict, malformed lockfile), that's not a gate concern. The
// gate should fall back to "show what the PM would have said and
// exit with the PM's code" — chdora is silent on PM noise.
// Chdora-internal failures (lockfile parse error, network failure
// inside chdora's own probes) stay as regular errors and are
// treated as fail-closed by policy.
type PMError struct {
	PM       string
	Command  string
	ExitCode int
	Output   []byte
	Err      error
}

func (e *PMError) Error() string {
	if len(e.Output) > 0 {
		return string(e.Output)
	}
	return fmt.Sprintf("%s %s: exit %d", e.PM, e.Command, e.ExitCode)
}

func (e *PMError) Unwrap() error { return e.Err }

// wrapPMError categorizes an error from a package-manager subprocess.
//
//   - non-zero exit  → *PMError carrying output + exit code (the PM
//     said "no" — surface its diagnostics to the user verbatim)
//   - failed to start (binary not found, context cancelled before
//     exec, OS-level fault) → wrapped err with a "<pm> <cmd>:"
//     prefix (chdora-internal failure — policy decides what to do)
//
// Returns nil if err is nil.
func wrapPMError(pm, command string, output []byte, err error) error {
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return &PMError{
			PM:       pm,
			Command:  command,
			ExitCode: exitErr.ExitCode(),
			Output:   output,
			Err:      err,
		}
	}
	return fmt.Errorf("%s %s: %w", pm, command, err)
}
