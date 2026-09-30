package artifacts

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"strings"
)

// verifyGoModule implements Go's documented h1 directory hash: SHA-256 of
// sorted "<file SHA-256>  <full ZIP path>\n" records. ZIP encoding metadata
// is deliberately excluded. Keep the same inspection resource bounds.
func verifyGoModule(data []byte, integrity string) error {
	want, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(integrity, "h1:"))
	if err != nil || len(want) != sha256.Size {
		return fmt.Errorf("invalid Go module h1 digest")
	}
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	if len(z.File) > MaxEntries {
		return fmt.Errorf("module archive entry limit exceeded")
	}
	sort.Slice(z.File, func(i, j int) bool { return z.File[i].Name < z.File[j].Name })
	summary := sha256.New()
	var total int64
	for i, f := range z.File {
		if strings.ContainsAny(f.Name, "\r\n") || !SafePath(strings.TrimSuffix(f.Name, "/")) || (i > 0 && z.File[i-1].Name == f.Name) {
			return fmt.Errorf("ambiguous Go module archive path")
		}
		if f.UncompressedSize64 > MaxFileBytes {
			return fmt.Errorf("module file exceeds limit")
		}
		r, err := f.Open()
		if err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(r, MaxFileBytes+1))
		_ = r.Close()
		total += n
		if err != nil {
			return err
		}
		if n > MaxFileBytes || total > MaxArchiveBytes {
			return fmt.Errorf("decoded module exceeds limit")
		}
		_, _ = fmt.Fprintf(summary, "%x  %s\n", h.Sum(nil), f.Name)
	}
	if subtle.ConstantTimeCompare(summary.Sum(nil), want) != 1 {
		return ErrMismatch
	}
	return nil
}
