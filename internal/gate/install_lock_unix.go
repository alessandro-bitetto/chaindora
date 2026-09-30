//go:build darwin || linux

package gate

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Keep the inode permanently: unlinking a lock file can give waiters and new
// callers different inodes and therefore different locks for the same project.
func acquireInstallLock(root string) (*os.File, error) {
	file, err := os.OpenFile(filepath.Join(root, ".chaindora-install.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("install lock must be a regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("cannot acquire project install lock (another Chaindora install may be running): %w", err)
	}
	return file, nil
}
