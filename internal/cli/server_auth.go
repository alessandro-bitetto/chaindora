package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func loadServerReadToken(path string, create bool) (string, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) && create {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return "", err
		}
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", err
		}
		f, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if openErr != nil {
			return "", openErr
		}
		_, writeErr := f.WriteString(hex.EncodeToString(random[:]) + "\n")
		closeErr := f.Close()
		if writeErr != nil {
			return "", writeErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return "", fmt.Errorf("%s must be a regular private file (chmod 600)", path)
	}
	if info.Size() > 4096 {
		return "", fmt.Errorf("token file exceeds 4096 bytes")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 32 || strings.ContainsAny(token, " \t\r\n") {
		return "", fmt.Errorf("operator token must contain at least 32 characters without whitespace")
	}
	return token, nil
}
