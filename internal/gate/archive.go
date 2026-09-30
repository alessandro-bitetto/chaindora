package gate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/artifacts"
)

func fetchPackageArchive(ctx context.Context, probe VersionProbe, ref PackageRef, limit int64) ([]byte, error) {
	var data []byte
	var err error
	if ref.ArtifactPath != "" {
		var f *os.File
		f, err = os.Open(ref.ArtifactPath)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		if limit <= 0 {
			limit = defaultArchiveLimit
		}
		data, err = io.ReadAll(io.LimitReader(f, limit+1))
		if int64(len(data)) > limit {
			return nil, fmt.Errorf("artifact snapshot exceeds limit")
		}
	} else {
		var url string
		if selector, ok := probe.(interface {
			ArtifactURL(context.Context, string, string, string) (string, error)
		}); ok && ref.Integrity != "" {
			url, err = selector.ArtifactURL(ctx, ref.Name, ref.Version, ref.Integrity)
		} else {
			url, err = probe.TarballURL(ctx, ref.Name, ref.Version)
		}
		if err == nil {
			data, err = fetchArchive(ctx, probe, url, limit)
		}
	}
	if err != nil {
		return nil, err
	}
	if ref.Integrity != "" {
		if err := artifacts.VerifyIntegrity(data, ref.Integrity); err != nil {
			return nil, err
		}
	}
	return data, nil
}

const (
	defaultArchiveLimit = 50 << 20
	maxArchiveFile      = 4 << 20
	maxArchiveEntries   = 10000
)

// cappedArchiveWriter also bounds probes that do not impose their own cap.
// Overflow is an error, never a successfully downloaded prefix.
type cappedArchiveWriter struct {
	buffer bytes.Buffer
	limit  int64
	err    error
}

func (w *cappedArchiveWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if int64(len(p)) > w.limit-int64(w.buffer.Len()) {
		w.err = fmt.Errorf("archive download exceeds %d bytes", w.limit)
		return 0, w.err
	}
	return w.buffer.Write(p)
}

func fetchArchive(ctx context.Context, probe VersionProbe, url string, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = defaultArchiveLimit
	}
	w := &cappedArchiveWriter{limit: limit}
	if err := probe.FetchTarball(ctx, url, w); err != nil {
		return nil, err
	}
	if w.err != nil {
		return nil, w.err
	}
	return w.buffer.Bytes(), nil
}

type archiveBudget struct {
	remaining int64
	entries   int
}

func newArchiveBudget(limit int64) *archiveBudget {
	if limit <= 0 {
		limit = defaultArchiveLimit
	}
	return &archiveBudget{remaining: limit}
}

func (b *archiveBudget) entry(size int64, name string) error {
	b.entries++
	if b.entries > maxArchiveEntries {
		return fmt.Errorf("archive exceeds %d entries", maxArchiveEntries)
	}
	if size < 0 || size > maxArchiveFile {
		return fmt.Errorf("archive entry %q exceeds per-file scan limit (%d bytes)", name, maxArchiveFile)
	}
	if size > b.remaining {
		return fmt.Errorf("archive scan budget exhausted at %q", name)
	}
	b.remaining -= size
	return nil
}

func scanGzipTar(data []byte, maxBytes int64) ([]StaticFinding, error) {
	return scanGzipTarBudget(data, newArchiveBudget(maxBytes), 0)
}

func scanGzipTarBudget(data []byte, budget *archiveBudget, depth int) ([]StaticFinding, error) {
	if depth > 3 {
		return nil, fmt.Errorf("nested archive depth exceeded")
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	return scanTarStream(gz, budget, depth)
}

func scanPlainTar(data []byte, maxBytes int64) ([]StaticFinding, error) {
	return scanTarStream(bytes.NewReader(data), newArchiveBudget(maxBytes), 0)
}

// Bound the entire decoded stream, including padding, metadata and trailing
// members. Draining to EOF validates the gzip checksum and detects truncation.
func scanTarStream(r io.Reader, budget *archiveBudget, depth int) ([]StaticFinding, error) {
	bounded := &io.LimitedReader{R: r, N: budget.remaining + 1}
	fs, err := scanTarReaderBudget(tar.NewReader(bounded), budget, depth)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(tarPaddingWriter{}, bounded); err != nil {
		return nil, fmt.Errorf("archive trailer: %w", err)
	}
	if bounded.N == 0 {
		return nil, fmt.Errorf("decoded archive exceeds scan limit")
	}
	return fs, nil
}

// Tar allows zero padding after its end marker. Reject any other trailing
// payload, including a concatenated tar member that was never inspected.
type tarPaddingWriter struct{}

func (tarPaddingWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b != 0 {
			return 0, fmt.Errorf("uninspected data after tar end marker")
		}
	}
	return len(p), nil
}

func scanTarReaderBudget(tr *tar.Reader, budget *archiveBudget, depth int) ([]StaticFinding, error) {
	var fs []StaticFinding
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fs, nil
		}
		if err != nil {
			return nil, fmt.Errorf("tar next: %w", err)
		}
		if err := budget.entry(hdr.Size, hdr.Name); err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		content, err := io.ReadAll(tr)
		if err != nil || int64(len(content)) != hdr.Size {
			return nil, fmt.Errorf("incomplete archive entry %q: %v", hdr.Name, err)
		}
		// RubyGems ship source inside data.tar.gz in an outer plain tar.
		if hdr.Name == "data.tar.gz" {
			nested, err := scanGzipTarBudget(content, budget, depth+1)
			if err != nil {
				return nil, err
			}
			fs = append(fs, nested...)
			continue
		}
		rel := strings.TrimPrefix(hdr.Name, "./")
		// RubyGems data.tar.gz has no package directory prefix.
		if depth == 0 {
			if i := strings.IndexByte(rel, '/'); i >= 0 {
				rel = rel[i+1:]
			}
		}
		fs = append(fs, scanFile(rel, content)...)
	}
}

func scanZip(data []byte, maxBytes int64) ([]StaticFinding, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("zip open: %w", err)
	}
	budget := newArchiveBudget(maxBytes)
	var fs []StaticFinding
	for _, f := range zr.File {
		if f.UncompressedSize64 > maxArchiveFile {
			return nil, fmt.Errorf("archive entry %q exceeds per-file scan limit", f.Name)
		}
		if err := budget.entry(int64(f.UncompressedSize64), f.Name); err != nil {
			return nil, err
		}
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("zip entry %q: %w", f.Name, err)
		}
		// Read past the declared size so the ZIP reader checks CRC at EOF.
		content, err := io.ReadAll(io.LimitReader(rc, int64(f.UncompressedSize64)+1))
		rc.Close()
		if err != nil || uint64(len(content)) != f.UncompressedSize64 {
			return nil, fmt.Errorf("invalid zip entry %q: %v", f.Name, err)
		}
		fs = append(fs, scanFile(f.Name, content)...)
	}
	return fs, nil
}
