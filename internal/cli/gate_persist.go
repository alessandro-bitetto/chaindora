package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Shell-rc auto-edit for `chdora gate install` (v0.15.1+). The
// original v0.9 design deliberately printed the export line and
// asked the user to add it by hand, because chdora's own host-
// state scanners flag rc tampering as a finding. Real-world
// experience: nobody adds the line, the shim never sticks across
// shells, the gate is effectively off.
//
// The fix: write a CLEARLY-MARKED block to the user's shell rc.
// The markers serve two purposes:
//
//   1. `chdora gate disable` can find and remove its own block
//      cleanly without touching the rest of the user's rc.
//   2. The host-state scanners (hostforensics.shellrc + trustdrift)
//      can recognize the marker and skip the block when looking
//      for suspicious-edit patterns — chdora doesn't flag itself.
//
// Block shape, identical across shells modulo the export syntax:
//
//   # >>> chdora gate (managed) >>>
//   # Added by `chdora gate install`. Remove with `chdora gate disable`.
//   # See https://chaindora.dev/gate for what this does.
//   <shell-specific PATH prepend>
//   # <<< chdora gate (managed) <<<
//
// Idempotent: running install twice is a no-op on the second
// run. Running disable when no block exists is also a no-op.

const (
	persistMarkerBegin = "# >>> chdora gate (managed) >>>"
	persistMarkerEnd   = "# <<< chdora gate (managed) <<<"
)

// detectShellRC returns the path to the user's shell init file
// where the PATH-prepend should land. Returns "" if the shell
// isn't one we know how to edit (caller should print manual
// instructions in that case).
//
// macOS/Linux: prefers ~/.zshrc / ~/.bashrc / ~/.config/fish/config.fish
// per $SHELL. Falls back to ~/.bash_profile on darwin-bash because
// macOS Terminal launches login shells by default and only
// ~/.bash_profile is sourced for those.
//
// Windows: PowerShell $PROFILE conventionally at
// $HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1.
func detectShellRC() (path, shell string, isWindows bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", false
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
			"powershell", true
	}
	shellPath := os.Getenv("SHELL")
	base := filepath.Base(shellPath)
	switch base {
	case "zsh":
		return filepath.Join(home, ".zshrc"), "zsh", false
	case "bash":
		if runtime.GOOS == "darwin" {
			bp := filepath.Join(home, ".bash_profile")
			if _, err := os.Stat(bp); err == nil {
				return bp, "bash", false
			}
		}
		return filepath.Join(home, ".bashrc"), "bash", false
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish"), "fish", false
	}
	return "", "", false
}

// persistGatePATH appends the chdora-managed PATH-prepend block
// to the user's shell rc. Idempotent — if the marker is already
// present, returns (rc, false, nil) without re-appending.
//
// Returns (rc-path, added, err): added=true iff the file was
// modified.
func persistGatePATH(shimDir string) (string, bool, error) {
	rc, shell, isWindows := detectShellRC()
	if rc == "" {
		return "", false, fmt.Errorf(
			"unrecognized shell (SHELL=%q on %s) — add the export line by hand to your shell rc",
			os.Getenv("SHELL"), runtime.GOOS)
	}
	existing, _ := os.ReadFile(rc)
	if strings.Contains(string(existing), persistMarkerBegin) {
		return rc, false, nil
	}
	if err := os.MkdirAll(filepath.Dir(rc), 0o755); err != nil {
		return rc, false, err
	}
	var block strings.Builder
	// Leading newline so we don't fuse with the user's last line.
	block.WriteString("\n")
	block.WriteString(persistMarkerBegin + "\n")
	block.WriteString("# Added by `chdora gate install`. Remove with `chdora gate disable`.\n")
	block.WriteString("# Routes every supported package-manager install through chdora's\n")
	block.WriteString("# supply-chain gate. Do not edit this block by hand — the markers\n")
	block.WriteString("# let chdora's own scanners recognize and skip it.\n")
	switch {
	case isWindows:
		block.WriteString(fmt.Sprintf("$env:PATH = %q + ';' + $env:PATH\n", shimDir))
	case shell == "fish":
		block.WriteString(fmt.Sprintf("set -gx PATH %q $PATH\n", shimDir))
	default:
		// zsh, bash, and any other POSIX-style shell.
		block.WriteString(fmt.Sprintf("export PATH=%q:$PATH\n", shimDir))
	}
	block.WriteString(persistMarkerEnd + "\n")

	f, err := os.OpenFile(rc, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return rc, false, err
	}
	defer f.Close()
	if _, err := io.WriteString(f, block.String()); err != nil {
		return rc, false, err
	}
	return rc, true, nil
}

// unpersistGatePATH removes the chdora-managed block from the
// shell rc. Idempotent — returns (rc, false, nil) if the block
// isn't present. Refuses to edit if the begin marker is found
// without a matching end marker (malformed state — surface to the
// user rather than guess).
func unpersistGatePATH() (string, bool, error) {
	rc, _, _ := detectShellRC()
	if rc == "" {
		return "", false, nil
	}
	data, err := os.ReadFile(rc)
	if err != nil {
		if os.IsNotExist(err) {
			return rc, false, nil
		}
		return rc, false, err
	}
	content := string(data)
	begin := strings.Index(content, persistMarkerBegin)
	if begin < 0 {
		return rc, false, nil
	}
	endIdx := strings.Index(content, persistMarkerEnd)
	if endIdx < 0 {
		return rc, false, fmt.Errorf(
			"found %q in %s but not %q — block looks malformed, refusing to auto-edit; remove it by hand",
			persistMarkerBegin, rc, persistMarkerEnd)
	}
	endIdx += len(persistMarkerEnd)
	// Pull the trailing newline so we don't leave a blank line.
	if endIdx < len(content) && content[endIdx] == '\n' {
		endIdx++
	}
	// Pull the leading newline we added on install.
	if begin > 0 && content[begin-1] == '\n' {
		begin--
	}
	newContent := content[:begin] + content[endIdx:]
	if err := os.WriteFile(rc, []byte(newContent), 0o644); err != nil {
		return rc, false, err
	}
	return rc, true, nil
}

// isPersistedInShellRC reports whether the chdora-managed block
// is present in the user's shell rc — used by `gate status` to
// distinguish "PATH set just in this shell" from "PATH set
// persistently across all future shells."
func isPersistedInShellRC() bool {
	rc, _, _ := detectShellRC()
	if rc == "" {
		return false
	}
	data, err := os.ReadFile(rc)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), persistMarkerBegin)
}
