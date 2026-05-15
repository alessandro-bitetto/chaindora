package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "chaindora",
	Short:         "chaindora — supply chain compromise scanner",
	Long:          `chaindora detects supply chain attacks across npm, pip, GitHub Actions, and other ecosystems by combining known-IOC matching, host-state forensics, behavioral heuristics, and static analysis.`,
	SilenceUsage:  true,
	SilenceErrors: false,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}
