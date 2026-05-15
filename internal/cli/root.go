package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version identifies the chaindora build; embedded in SARIF tool metadata.
// Override at build time with -ldflags "-X github.com/alessandro-bitetto/chaindora/internal/cli.Version=v0.1.0".
var Version = "0.1.0-dev"

var rootCmd = &cobra.Command{
	Use:           "chdora",
	Short:         "chdora — supply chain compromise scanner (project: chaindora)",
	Long:          `chdora is the chaindora project's CLI. It detects supply chain attacks across npm, pip, GitHub Actions, and other ecosystems by combining known-IOC matching, host-state forensics, behavioral heuristics, and static analysis.`,
	SilenceUsage:  true,
	SilenceErrors: false,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}
