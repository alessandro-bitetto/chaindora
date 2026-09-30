package artifacts

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestGoModuleDirectoryIntegrity(t *testing.T) {
	// The expected digest hashes sorted paths/content, independent of ZIP order.
	one, two := sha256.Sum256([]byte("module example.test/m\n")), sha256.Sum256([]byte("package m\n"))
	summary := fmt.Sprintf("%x  example.test/m@v1.0.0/go.mod\n%x  example.test/m@v1.0.0/m.go\n", one, two)
	sum := sha256.Sum256([]byte(summary))
	integrity := "h1:" + base64.StdEncoding.EncodeToString(sum[:])
	for _, changed := range []bool{false, true} {
		var b bytes.Buffer
		z := zip.NewWriter(&b)
		f, _ := z.Create("example.test/m@v1.0.0/m.go")
		if changed {
			if _, err := f.Write([]byte("package changed\n")); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := f.Write([]byte("package m\n")); err != nil {
				t.Fatal(err)
			}
		}
		f, _ = z.Create("example.test/m@v1.0.0/go.mod")
		if _, err := f.Write([]byte("module example.test/m\n")); err != nil {
			t.Fatal(err)
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		err := VerifyIntegrity(b.Bytes(), integrity)
		if changed && err != ErrMismatch {
			t.Fatalf("modified module: %v", err)
		}
		if !changed && err != nil {
			t.Fatal(err)
		}
	}
}
