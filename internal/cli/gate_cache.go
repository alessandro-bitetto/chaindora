package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/alessandro-bitetto/chaindora/internal/gate"
)

// `chdora gate cache` exposes the verdict cache at
// ~/.chaindora/gate-cache/ — the disk-backed store that makes
// repeated installs fast AND turns a same-name@version-different-
// bytes collision into a republish-guard finding.
//
// Three subcommands:
//   - stats: per-ecosystem entry counts
//   - clear: wipe the whole cache (next install rebuilds)
//   - path:  print the cache root (handy for piping into `du -sh`)

var gateCacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Inspect or manage the gate verdict cache",
	Long: `The gate verdict cache stores Approve decisions keyed on
(ecosystem, name, version, integrity-hash). Repeat installs of the
same package versions hit the cache and skip the checker stack.

A subsequent install of the same name@version with a DIFFERENT
integrity hash triggers the republish-guard check — a Block
finding that surfaces possible registry-side tampering or
maintainer-account compromise.`,
}

var gateCacheStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show entry counts per ecosystem",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := gate.NewCache(gate.DefaultCacheRoot(), 0)
		stats, err := c.Stats()
		if err != nil {
			return err
		}
		if len(stats) == 0 {
			fmt.Fprintf(os.Stderr, "cache empty (%s)\n", c.Root)
			return nil
		}
		fmt.Fprintf(os.Stderr, "cache root: %s\n\n", c.Root)
		tw := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ECOSYSTEM\tENTRIES")
		total := 0
		for _, s := range stats {
			fmt.Fprintf(tw, "%s\t%d\n", s.Ecosystem, s.Entries)
			total += s.Entries
		}
		fmt.Fprintf(tw, "TOTAL\t%d\n", total)
		return tw.Flush()
	},
}

var gateCacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Remove the entire gate verdict cache",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := gate.NewCache(gate.DefaultCacheRoot(), 0)
		if err := c.Clear(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "cleared %s\n", c.Root)
		return nil
	},
}

var gateCachePathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print the cache root path",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(gate.DefaultCacheRoot())
		return nil
	},
}

func init() {
	gateCacheCmd.AddCommand(gateCacheStatsCmd, gateCacheClearCmd, gateCachePathCmd)
	gateCmd.AddCommand(gateCacheCmd)
}
