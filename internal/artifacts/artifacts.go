// Package artifacts verifies downloaded bytes and installed npm file contents.
// A manifest is derived only after the archive matches the lockfile digest.
package artifacts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const MaxArchiveBytes = 50 << 20
const MaxFileBytes = 4 << 20
const MaxEntries = 10000

var ErrMismatch = errors.New("artifact integrity mismatch")

// VerifyIntegrity supports SRI and the SHA-256 hex notation used by PyPI and
// Cargo. Multiple SRI hashes use the strongest algorithm, as required by SRI.
// Unsupported representations are errors, never a successful verification.
func VerifyIntegrity(data []byte, integrity string) error {
	if strings.HasPrefix(integrity, "h1:") {
		return verifyGoModule(data, integrity)
	}
	if strings.TrimSpace(integrity) == "" {
		return fmt.Errorf("missing artifact integrity")
	}
	best := 0
	var candidates [][]byte
	var sum []byte
	for _, token := range strings.Fields(integrity) {
		var algorithm, encoded string
		var want []byte
		var err error
		if i := strings.IndexAny(token, ":="); i > 0 && !strings.Contains(token[:i], "-") {
			algorithm, encoded = token[:i], token[i+1:]
			want, err = hex.DecodeString(encoded)
		} else if i := strings.IndexByte(token, '-'); i > 0 {
			algorithm, encoded = token[:i], token[i+1:]
			want, err = base64.StdEncoding.DecodeString(encoded)
		} else {
			return fmt.Errorf("unsupported artifact integrity encoding")
		}
		var h hash.Hash
		var rank int
		switch algorithm {
		case "sha1":
			h, rank = sha1.New(), 1
		case "sha256":
			h, rank = sha256.New(), 2
		case "sha384":
			h, rank = sha512.New384(), 3
		case "sha512":
			h, rank = sha512.New(), 4
		default:
			return fmt.Errorf("unsupported artifact digest algorithm %q", algorithm)
		}
		if err != nil || len(want) != h.Size() {
			return fmt.Errorf("invalid %s digest", algorithm)
		}
		if rank > best {
			best = rank
			candidates = nil
			_, _ = h.Write(data)
			sum = h.Sum(nil)
		}
		if rank == best {
			candidates = append(candidates, want)
		}
	}
	for _, want := range candidates {
		if subtle.ConstantTimeCompare(sum, want) == 1 {
			return nil
		}
	}
	return ErrMismatch
}

func SHA512(data []byte) string {
	sum := sha512.Sum512(data)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

func Download(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("artifact request: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxArchiveBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxArchiveBytes {
		return nil, fmt.Errorf("artifact exceeds download limit")
	}
	return data, nil
}

type Manifest struct {
	Name    string
	Version string
	Files   map[string]string // relative path -> SHA-256 hex
}

// NPMManifest accepts a verified npm tarball. Archive links and ambiguous paths
// are refused; no contents are ever extracted or executed by this reader.
func NPMManifest(data []byte, integrity string) (*Manifest, error) {
	if err := VerifyIntegrity(data, integrity); err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = gz.Close() }()
	bounded := &io.LimitedReader{R: gz, N: MaxArchiveBytes + 1}
	tr := tar.NewReader(bounded)
	m := &Manifest{Files: map[string]string{}}
	prefix := ""
	for count := 0; ; count++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if count >= MaxEntries || hdr.Size < 0 || hdr.Size > MaxFileBytes {
			return nil, fmt.Errorf("archive entry limit exceeded")
		}
		name := strings.TrimSuffix(hdr.Name, "/")
		if !SafePath(name) {
			return nil, fmt.Errorf("unsafe archive path %q", hdr.Name)
		}
		parts := strings.SplitN(name, "/", 2)
		if prefix == "" {
			prefix = parts[0]
		}
		if parts[0] != prefix {
			return nil, fmt.Errorf("archive has multiple roots")
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg || len(parts) != 2 {
			return nil, fmt.Errorf("unsupported archive entry %q", hdr.Name)
		}
		name = parts[1]
		if _, exists := m.Files[name]; exists {
			return nil, fmt.Errorf("duplicate archive path %q", name)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(content)
		m.Files[name] = hex.EncodeToString(sum[:])
		if name == "package.json" {
			var pkg struct {
				Name    string
				Version string
			}
			if err := json.Unmarshal(content, &pkg); err != nil {
				return nil, err
			}
			m.Name, m.Version = pkg.Name, pkg.Version
		}
	}
	// Validate the gzip checksum and reject hidden tar members/trailing data.
	tail, err := io.ReadAll(bounded)
	if err != nil {
		return nil, err
	}
	if bounded.N == 0 {
		return nil, fmt.Errorf("decoded artifact exceeds limit")
	}
	for _, b := range tail {
		if b != 0 {
			return nil, fmt.Errorf("uninspected archive trailer")
		}
	}
	if m.Name == "" || m.Version == "" {
		return nil, fmt.Errorf("artifact has no package identity")
	}
	return m, nil
}

func SafePath(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.HasPrefix(name, "../") &&
		!strings.HasPrefix(name, "/") && !strings.ContainsAny(name, "\\:\x00") && path.Clean(name) == name
}

type Difference struct{ Path, Reason string }

// CompareFiles checks every published file and reports unexpected local files.
// Nested node_modules belong to separately resolved dependencies; bundled files
// recorded in the manifest are still checked individually.
func CompareFiles(root string, manifest *Manifest) ([]Difference, error) {
	if info, err := os.Lstat(root); os.IsNotExist(err) {
		return []Difference{{root, "locked package is missing"}}, nil
	} else if err != nil {
		return nil, err
	} else if !info.IsDir() {
		return []Difference{{root, "installed package is a symlink or not a directory"}}, nil
	}
	var out []Difference
	for name, expected := range manifest.Files {
		filename := filepath.Join(root, filepath.FromSlash(name))
		if err := regularPath(root, name); err != nil {
			out = append(out, Difference{filename, "missing file, symlink, or unsupported file type"})
			continue
		}
		f, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(f, MaxFileBytes+1))
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		if n > MaxFileBytes || hex.EncodeToString(h.Sum(nil)) != expected {
			out = append(out, Difference{filename, "file content differs from verified artifact"})
		}
	}
	count := 0
	err := filepath.WalkDir(root, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filename == root {
			return nil
		}
		count++
		if count > MaxEntries {
			return fmt.Errorf("installed file limit exceeded")
		}
		rel, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			if rel == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if _, ok := manifest.Files[rel]; !ok {
			out = append(out, Difference{filename, "file is absent from verified artifact"})
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// DirectoryPath refuses symlinked parents inside an installation. The caller's
// project directory is trusted; all relative components are checked with Lstat.
func DirectoryPath(base, relative string) error {
	if !SafePath(relative) {
		return fmt.Errorf("unsafe installed directory path")
	}
	for _, part := range strings.Split(relative, "/") {
		base = filepath.Join(base, part)
		info, err := os.Lstat(base)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("installed directory contains a symlink or non-directory: %s", base)
		}
	}
	return nil
}

func regularPath(root, name string) error {
	if !SafePath(name) {
		return fmt.Errorf("unsafe path")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("package root is not a directory")
	}
	parts := strings.Split(name, "/")
	p := root
	for i, part := range parts {
		p = filepath.Join(p, part)
		info, err = os.Lstat(p)
		if err != nil {
			return err
		}
		if i == len(parts)-1 {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("not regular")
			}
		} else if !info.IsDir() {
			return fmt.Errorf("not directory")
		}
	}
	return nil
}
