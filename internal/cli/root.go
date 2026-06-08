package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version identifies the chaindora build; embedded in SARIF tool metadata.
// Override at build time with -ldflags "-X github.com/alessandro-bitetto/chaindora/internal/cli.Version=v0.1.0".
var Version = "0.1.0-dev"

// ExitError is the typed error a cobra RunE handler returns when it
// wants the process to exit with a specific non-zero code, distinct
// from the default "generic error → exit 2" path. Wrapping an
// underlying err keeps the chain unwrappable for tests that need to
// assert on the cause.
//
// Replaces the previous pattern of calling os.Exit directly from
// inside RunE handlers, which scattered exit-code knowledge across
// internal/cli/* files and made unit testing the success/failure
// paths brittle. v0.17.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit %d", e.Code)
}

func (e *ExitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// SilentExit returns an ExitError with the given code and no message.
// Use for paths where the handler already rendered everything the
// user needs to see (gate verdict report, scan summary) and the only
// remaining job is the exit code.
func SilentExit(code int) error {
	return &ExitError{Code: code}
}

var rootCmd = &cobra.Command{
	Use:           "chdora",
	Version:       Version,
	Short:         "chdora — supply chain compromise scanner (project: chaindora)",
	Long:          `chdora is the chaindora project's CLI. It detects supply chain attacks across npm, pip, GitHub Actions, and other ecosystems by combining known-IOC matching, host-state forensics, behavioral heuristics, and static analysis.`,
	SilenceUsage:  true,
	SilenceErrors: false,
}

func init() {
	rootCmd.SetVersionTemplate("chdora {{.Version}}\n")
}

// Execute runs the cobra root and translates returned errors to the
// process's exit code. A nil error → exit 0. An *ExitError → that
// specific code, suppressing the default error-print for codes that
// carry their own rendered context (verdict reports, scan summaries).
// Any other error → print to stderr, exit 2.
func Execute() {
	err := rootCmd.Execute()
	if err == nil {
		return
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		// If the ExitError carried a message, surface it. Bare
		// SilentExit(N) skips this — the handler already printed.
		if exit.Err != nil {
			fmt.Fprintln(os.Stderr, "error:", exit.Err)
		}
		os.Exit(exit.Code)
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(2)
}
