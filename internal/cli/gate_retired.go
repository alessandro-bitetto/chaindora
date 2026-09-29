package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// removeManagedShims migrates old installations without deleting user files.
// Inspect only regular files in our shim directory, and require our marker.
// retiredOnly keeps the currently supported managers during gate installation.
func removeManagedShims(dir string, retiredOnly bool) (int, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".cmd")
		if retiredOnly && isGatedPM(name) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		f, err := os.Open(path)
		if err != nil {
			return removed, err
		}
		data, err := io.ReadAll(io.LimitReader(f, 4096))
		f.Close()
		if err != nil {
			return removed, err
		}
		if !bytes.Contains(data, []byte("chdora gate shim")) {
			continue
		}
		if err := os.Remove(path); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
