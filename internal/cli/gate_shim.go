package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// `chdora gate install` registers shims that route the user's
// `npm install ...` (and yarn / pnpm / pip in future) through
// `chdora gate exec`. The shims live in ~/.chaindora/bin/ — the
// user is responsible for putting that directory on the FRONT of
// $PATH (we print clear instructions, we don't edit shells rcs).
//
// We deliberately don't write to /usr/local/bin or anywhere that
// requires sudo. Per-user opt-in is the right scope: a system-wide
// shim would break sysadmin workflows, package upgrades from
// homebrew, etc.

// Package managers we know how to shim. Even ecosystems chdora
// doesn't gate yet get a shim — the shim falls through to
// passThroughToReal so it's safe to enable everywhere.
var shimManagers = []string{"npm", "yarn", "pnpm", "pip", "pip3", "cargo", "bundle", "gem", "mvn", "go",
	"dotnet", "composer", "poetry", "uv", "gradle",
	"pod", "swift", "dart", "flutter", "mix",
	"bun", "conda", "mamba", "micromamba", "brew", "conan",
	"pipenv", "pdm", "deno", "stack", "cabal", "sbt", "opam",
	"rebar3", "paket", "vcpkg",
	"cpanm", "luarocks", "carthage", "elm", "nimble", "shards", "zig",
	"julia", "R", "Rscript"}

var gateInstallNoPersist bool

var gateInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Register shims so npm/yarn/pnpm/pip route installs through chdora gate",
	Long: `Writes one small shim script per supported package manager into
~/.chaindora/bin/. Each shim simply exec's ` + "`chdora gate exec <manager>`" + ` —
which gates install verbs and passes everything else through transparently.

Also appends a clearly-marked block to your shell rc (~/.zshrc /
~/.bashrc / fish config / PowerShell $PROFILE) that prepends
~/.chaindora/bin to $PATH, so the shim sticks across new terminals
and reboots. Use --no-persist to skip the rc edit; the command then
just prints the export line for you to add by hand.

The rc block carries fence-comment markers (` + "`# >>> chdora gate (managed) >>>`" + `)
so chdora's own host-state scanners recognize and skip it, and so
` + "`chdora gate disable`" + ` can remove the block cleanly.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := chaindoraShimDir()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}

		// Resolve our own absolute path for the shim's #!/usr/bin/env
		// chdora line. Falling back to `chdora` on PATH is fine but
		// pins the shim to whichever chdora the user installs next —
		// usually what they want.
		chdoraPath, err := os.Executable()
		if err != nil {
			chdoraPath = "chdora"
		}

		written := 0
		for _, pm := range shimManagers {
			path := filepath.Join(dir, pm)
			content := shimContent(chdoraPath, pm)
			if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
				return fmt.Errorf("write shim %s: %w", path, err)
			}
			written++
		}

		fmt.Fprintf(os.Stderr, "\n[chdora] %d shim(s) written to %s\n", written, dir)

		// Persistence: edit the shell rc unless --no-persist was passed.
		if gateInstallNoPersist {
			fmt.Fprintln(os.Stderr, "\n--no-persist: skipped shell-rc edit. Add this line manually to activate:")
			fmt.Fprintf(os.Stderr, "\n    export PATH=\"%s:$PATH\"\n\n", dir)
		} else {
			rc, added, perr := persistGatePATH(dir)
			if perr != nil {
				fmt.Fprintf(os.Stderr, "\nwarn: couldn't auto-edit shell rc: %v\n", perr)
				fmt.Fprintln(os.Stderr, "Add this line to your shell rc by hand to activate:")
				fmt.Fprintf(os.Stderr, "\n    export PATH=\"%s:$PATH\"\n\n", dir)
			} else if added {
				fmt.Fprintf(os.Stderr, "\n[chdora] appended PATH-prepend block to %s\n", rc)
				fmt.Fprintf(os.Stderr, "Run `source %s` (or open a new shell) to activate now.\n", rc)
			} else {
				fmt.Fprintf(os.Stderr, "\n[chdora] %s already contains the chdora-gate block — no rc edit needed.\n", rc)
			}
		}
		fmt.Fprintln(os.Stderr, "\nFrom a fresh shell:")
		fmt.Fprintln(os.Stderr, "    npm install <pkg>     # goes through chdora gate")
		fmt.Fprintln(os.Stderr, "    npm test              # passes through unchanged")
		fmt.Fprintln(os.Stderr, "    chdora gate status    # confirm shim is in PATH")
		fmt.Fprintln(os.Stderr, "\nTo undo:")
		fmt.Fprintln(os.Stderr, "    chdora gate disable")
		return nil
	},
}

var gateDisableNoPersist bool

var gateDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Remove the chdora gate shims",
	Long: `Removes every shim chdora installed under ~/.chaindora/bin/. After
removal, npm / yarn / pnpm / pip resolve directly to the real
binaries on PATH again.

Also removes the chdora-managed PATH-prepend block from your shell
rc (the one ` + "`chdora gate install`" + ` added). Pass --no-persist to
keep the rc edit in place — useful when you're temporarily disabling
the shims but plan to re-enable shortly.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := chaindoraShimDir()
		if err != nil {
			return err
		}
		removed := 0
		for _, pm := range shimManagers {
			path := filepath.Join(dir, pm)
			if err := os.Remove(path); err != nil {
				if !os.IsNotExist(err) {
					fmt.Fprintf(os.Stderr, "warn: %s: %v\n", path, err)
				}
				continue
			}
			removed++
		}
		fmt.Fprintf(os.Stderr, "[chdora] removed %d shim(s) from %s\n", removed, dir)

		if !gateDisableNoPersist {
			rc, cleaned, uerr := unpersistGatePATH()
			if uerr != nil {
				fmt.Fprintf(os.Stderr, "warn: couldn't auto-clean shell rc: %v\n", uerr)
			} else if cleaned {
				fmt.Fprintf(os.Stderr, "[chdora] removed chdora-gate block from %s\n", rc)
			} else if rc != "" {
				fmt.Fprintf(os.Stderr, "[chdora] no chdora-gate block found in %s — nothing to clean\n", rc)
			}
		}
		return nil
	},
}

var gateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show which package managers are currently gated",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := chaindoraShimDir()
		if err != nil {
			return err
		}
		// Each shim's status is the cross of "does the file exist?"
		// (we installed it) and "does it actually shadow the real
		// binary?" (the directory is on PATH ahead of /usr/bin etc).
		shimOnPATH := isDirOnPATH(dir)
		persisted := isPersistedInShellRC()
		fmt.Fprintf(os.Stderr, "shim directory: %s\n", dir)
		switch {
		case shimOnPATH && persisted:
			fmt.Fprintln(os.Stderr, "PATH includes this directory AND shell rc has the chdora-gate block — installed shims are ACTIVE and persistent.")
		case shimOnPATH && !persisted:
			fmt.Fprintln(os.Stderr, "PATH includes this directory in THIS shell only (no chdora-gate block in your shell rc).")
			fmt.Fprintln(os.Stderr, "Run `chdora gate install` (without --no-persist) to make activation stick across shells + reboots.")
		case !shimOnPATH && persisted:
			fmt.Fprintln(os.Stderr, "Shell rc has the chdora-gate block but PATH isn't picking it up in this shell.")
			fmt.Fprintln(os.Stderr, "Open a new terminal (or `source` your rc) to activate.")
		default:
			fmt.Fprintln(os.Stderr, "PATH does NOT include this directory — shims are INACTIVE.")
			fmt.Fprintln(os.Stderr, "Run `chdora gate install` to install + persist, or set PATH for this shell:")
			fmt.Fprintf(os.Stderr, "    export PATH=\"%s:$PATH\"\n", dir)
		}
		fmt.Fprintln(os.Stderr)
		for _, pm := range shimManagers {
			path := filepath.Join(dir, pm)
			installed := fileExists(path)
			real, _ := findRealPackageManager(pm)
			gated := "false"
			if isGatedPM(pm) {
				gated = "true"
			}
			switch {
			case installed && shimOnPATH:
				fmt.Fprintf(os.Stderr, "  %-6s shim=installed active=yes gates-install=%s (real: %s)\n", pm, gated, real)
			case installed && !shimOnPATH:
				fmt.Fprintf(os.Stderr, "  %-6s shim=installed active=NO  gates-install=%s (real: %s)\n", pm, gated, real)
			default:
				fmt.Fprintf(os.Stderr, "  %-6s shim=missing               (real: %s)\n", pm, real)
			}
		}
		fmt.Fprintln(os.Stderr, "\nTo audit shim overhead on non-install verbs (expected <100ms):")
		fmt.Fprintln(os.Stderr, "    time npm run --silent noop   # without chdora")
		fmt.Fprintln(os.Stderr, "    time npm run --silent noop   # with chdora shim on PATH")
		return nil
	},
}

// shimContent returns the shell script body for one shim. The shim
// is intentionally trivial — anything fancy belongs in chdora, not
// in a script the user could see and reasonably wonder about.
func shimContent(chdoraPath, manager string) string {
	if runtime.GOOS == "windows" {
		// Windows shims need .bat / .cmd treatment. Out of scope for
		// v0.9 (chdora gate exec works fine on Windows but the shim
		// mechanism requires either PowerShell or .cmd wrappers).
		// Write a marker file so disable/status still work.
		return "@echo off\r\n" + chdoraPath + " gate exec " + manager + " %*\r\n"
	}
	return strings.Join([]string{
		"#!/bin/sh",
		"# chdora gate shim — routes installs through `chdora gate exec`.",
		"# Generated by `chdora gate install`. Remove with `chdora gate disable`.",
		"exec " + shellQuote(chdoraPath) + " gate exec " + manager + " \"$@\"",
		"",
	}, "\n")
}

func shellQuote(s string) string {
	if !strings.ContainsAny(s, " \t'\"\\$`&|;<>()*?[]{}~#!") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func isDirOnPATH(dir string) bool {
	want, err := filepath.Abs(dir)
	if err != nil {
		want = dir
	}
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		if abs == want {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func init() {
	gateInstallCmd.Flags().BoolVar(&gateInstallNoPersist, "no-persist", false,
		"skip the shell-rc edit; just write the shim files and print the export line to add by hand")
	gateDisableCmd.Flags().BoolVar(&gateDisableNoPersist, "no-persist", false,
		"don't touch the shell rc when disabling (leave the chdora-managed PATH block in place)")
	gateCmd.AddCommand(gateInstallCmd, gateDisableCmd, gateStatusCmd)
}
