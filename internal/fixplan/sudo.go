package fixplan

import (
	"os"
	"os/user"
	"runtime"
	"strconv"
)

// chownToSudoUser hands ownership of `path` back to the original user
// when the binary is running as root under sudo. Without this, plans
// saved by `sudo chdora audit --save-plan` land on disk as
// root:wheel 0600 — and the next `chdora plans list` (run normally,
// without sudo) silently fails to read them because the inode is
// owner-only.
//
// No-op on Windows (os.Chown returns an error there), no-op when we
// aren't root, and no-op when SUDO_USER isn't set. Any chown error
// is silently ignored: failing to fix ownership is strictly worse UX
// than not trying, but we never want to abort a successful save over
// it.
//
// Callers should invoke this after creating each artifact (the
// directory after MkdirAll, the file after the atomic rename) so
// every newly-created node lands with the right owner.
func chownToSudoUser(path string) {
	if runtime.GOOS == "windows" {
		return
	}
	if os.Geteuid() != 0 {
		return
	}
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser == "" || sudoUser == "root" {
		return
	}
	u, err := user.Lookup(sudoUser)
	if err != nil {
		return
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return
	}
	_ = os.Chown(path, uid, gid)
}
