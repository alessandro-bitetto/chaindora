package cli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultUpgradeAPI = "https://api.github.com/repos/alessandro-bitetto/chaindora/releases/latest"
	upgradeUserAgent  = "chdora-upgrade/"
	upgradeBinaryName = "chdora"
)

var (
	upgradeAPIURL  string
	upgradeCheck   bool
	upgradeDryRun  bool
	upgradeForce   bool
	upgradeVersion string
	upgradeVerbose bool
)

// releaseAsset is the subset of the GitHub Releases API asset object we use.
type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

type releaseInfo struct {
	TagName    string         `json:"tag_name"`
	Name       string         `json:"name"`
	HTMLURL    string         `json:"html_url"`
	Assets     []releaseAsset `json:"assets"`
	Draft      bool           `json:"draft"`
	Prerelease bool           `json:"prerelease"`
}

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade the chdora binary to the latest GitHub release",
	Long: `Downloads the latest chaindora release archive from
github.com/alessandro-bitetto/chaindora, verifies its SHA-256 against the
published checksums file, and atomically replaces the running binary.

The archive matching the current GOOS/GOARCH (linux/darwin/windows ×
amd64/arm64) is selected automatically. On macOS and Linux the new
binary is renamed into place; on Windows the previous .exe is parked as
chdora.exe.old because Windows refuses to overwrite a running
executable.

If the binary appears to be managed by a package manager (Homebrew,
snap), the upgrade is refused — use the package manager instead, or
pass --force.

This command does NOT refresh the curated incident pack — run
'chdora update' for that.`,
	RunE: runUpgrade,
}

func runUpgrade(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	self, err := resolveSelf()
	if err != nil {
		return err
	}

	if mgr := packageManagerHint(self); mgr != "" && !upgradeForce {
		return fmt.Errorf("binary at %s appears to be managed by %s — upgrade via that package manager (or pass --force)", self, mgr)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	rel, err := fetchRelease(ctx, client, upgradeAPIURL, upgradeVersion)
	if err != nil {
		return fmt.Errorf("fetch release: %w", err)
	}

	target := strings.TrimPrefix(rel.TagName, "v")
	current := strings.TrimPrefix(Version, "v")
	fmt.Printf("current: %s, latest: %s\n", current, target)

	if !upgradeForce && target == current {
		fmt.Println("already on the latest release")
		return nil
	}

	if upgradeCheck {
		fmt.Printf("new release available: %s — %s\n", rel.TagName, rel.HTMLURL)
		return nil
	}

	archiveAsset, checksumAsset, err := pickAssets(rel.Assets, target, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	if upgradeVerbose {
		fmt.Fprintf(os.Stderr, "asset: %s (%d bytes)\n", archiveAsset.Name, archiveAsset.Size)
		fmt.Fprintf(os.Stderr, "checksums: %s\n", checksumAsset.Name)
	}

	archiveBytes, err := upgradeDownload(ctx, client, archiveAsset.BrowserDownloadURL)
	if err != nil {
		return fmt.Errorf("download archive: %w", err)
	}
	checksumBytes, err := upgradeDownload(ctx, client, checksumAsset.BrowserDownloadURL)
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}

	if err := verifyChecksum(archiveBytes, archiveAsset.Name, checksumBytes); err != nil {
		return fmt.Errorf("checksum: %w", err)
	}
	if upgradeVerbose {
		fmt.Fprintln(os.Stderr, "checksum: ok")
	}

	binName := upgradeBinaryName
	if runtime.GOOS == "windows" {
		binName = upgradeBinaryName + ".exe"
	}
	newBin, err := extractBinary(archiveBytes, archiveAsset.Name, binName)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}

	if upgradeDryRun {
		fmt.Printf("dry-run: would replace %s (%d bytes new)\n", self, len(newBin))
		return nil
	}

	if err := replaceBinary(self, newBin); err != nil {
		return fmt.Errorf("install: %w", err)
	}

	fmt.Printf("upgraded chdora: %s -> %s\n", current, target)
	fmt.Printf("release notes: %s\n", rel.HTMLURL)
	fmt.Println("tip: run 'chdora update' to refresh the incident pack")
	return nil
}

// resolveSelf returns the absolute path to the running binary with any
// symlinks resolved, so the install step replaces the actual file rather
// than the symlink.
func resolveSelf() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve self: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(self)
	if err != nil {
		return "", fmt.Errorf("resolve symlinks: %w", err)
	}
	return resolved, nil
}

func fetchRelease(ctx context.Context, client *http.Client, base, version string) (*releaseInfo, error) {
	url := base
	if version != "" {
		tag := version
		if !strings.HasPrefix(tag, "v") {
			tag = "v" + tag
		}
		if strings.Contains(url, "/releases/latest") {
			url = strings.Replace(url, "/releases/latest", "/releases/tags/"+tag, 1)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", upgradeUserAgent+Version)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	var rel releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	if strings.TrimSpace(rel.TagName) == "" {
		return nil, errors.New("release has no tag_name")
	}
	return &rel, nil
}

func upgradeDownload(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	if url == "" {
		return nil, errors.New("empty asset URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", upgradeUserAgent+Version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	// 60 MiB safety cap; chdora archives are under 10 MiB today.
	return io.ReadAll(io.LimitReader(resp.Body, 60<<20))
}

// pickAssets selects the goreleaser-produced archive for the current
// GOOS/GOARCH plus the matching checksums.txt. Asset names follow the
// .goreleaser.yml template: chaindora_<ver>_<os>_<arch>.<ext>, where
// arch is x86_64 for amd64 and the literal arch otherwise, and ext is
// tar.gz on linux/darwin and zip on windows.
func pickAssets(assets []releaseAsset, version, goos, goarch string) (archive, checksum *releaseAsset, err error) {
	arch := goarch
	if arch == "amd64" {
		arch = "x86_64"
	}
	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}
	archiveName := fmt.Sprintf("chaindora_%s_%s_%s.%s", version, goos, arch, ext)
	checksumName := fmt.Sprintf("chaindora_%s_checksums.txt", version)
	for i := range assets {
		a := &assets[i]
		if a.Name == archiveName {
			archive = a
		}
		if a.Name == checksumName {
			checksum = a
		}
	}
	if archive == nil {
		return nil, nil, fmt.Errorf("no matching asset for %s/%s (expected %q)", goos, goarch, archiveName)
	}
	if checksum == nil {
		return nil, nil, fmt.Errorf("no checksums file (expected %q)", checksumName)
	}
	return archive, checksum, nil
}

// verifyChecksum confirms that archive's SHA-256 matches the entry for
// archiveName in a goreleaser-style checksums file (lines of
// "<sha256>  <filename>").
func verifyChecksum(archive []byte, archiveName string, checksumFile []byte) error {
	sum := sha256.Sum256(archive)
	want := hex.EncodeToString(sum[:])
	for _, line := range strings.Split(string(checksumFile), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[1] == archiveName {
			if !strings.EqualFold(fields[0], want) {
				return fmt.Errorf("sha256 mismatch for %s: got %s, want %s", archiveName, want, fields[0])
			}
			return nil
		}
	}
	return fmt.Errorf("no checksum entry for %s", archiveName)
}

func extractBinary(archive []byte, archiveName, binName string) ([]byte, error) {
	if strings.HasSuffix(archiveName, ".zip") {
		return extractFromZip(archive, binName)
	}
	return extractFromTarGz(archive, binName)
}

func extractFromTarGz(archive []byte, binName string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if filepath.Base(hdr.Name) == binName {
			return io.ReadAll(io.LimitReader(tr, 200<<20))
		}
	}
	return nil, fmt.Errorf("%s not found in archive", binName)
}

func extractFromZip(archive []byte, binName string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) == binName {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, 200<<20))
		}
	}
	return nil, fmt.Errorf("%s not found in archive", binName)
}

// replaceBinary writes body to a temp file in the same directory as self
// and atomically renames it into place. On Windows the running .exe
// cannot be removed, so the previous binary is renamed to <self>.old and
// will be cleaned up the next time the user upgrades (best-effort
// os.Remove on the next call).
func replaceBinary(self string, body []byte) error {
	dir := filepath.Dir(self)
	tmp, err := os.CreateTemp(dir, "chaindora-upgrade-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		cleanup()
		return err
	}
	if runtime.GOOS == "windows" {
		old := self + ".old"
		_ = os.Remove(old)
		if err := os.Rename(self, old); err != nil {
			cleanup()
			return err
		}
		if err := os.Rename(tmpName, self); err != nil {
			_ = os.Rename(old, self)
			cleanup()
			return err
		}
		return nil
	}
	if err := os.Rename(tmpName, self); err != nil {
		cleanup()
		return err
	}
	return nil
}

// packageManagerHint returns the name of a package manager that owns the
// given binary path, or "" if none is recognized. We're conservative
// here: the user can always override with --force.
func packageManagerHint(path string) string {
	p := filepath.ToSlash(path)
	switch {
	case strings.Contains(p, "/Cellar/"),
		strings.HasPrefix(p, "/opt/homebrew/"),
		strings.Contains(p, "/linuxbrew/"):
		return "Homebrew (brew upgrade chdora)"
	case strings.HasPrefix(p, "/snap/"),
		strings.HasPrefix(p, "/var/lib/snapd/"):
		return "snap (snap refresh chdora)"
	}
	return ""
}

func init() {
	upgradeCmd.Flags().StringVar(&upgradeAPIURL, "api-url", defaultUpgradeAPI,
		"GitHub Releases API URL (advanced — override for forks or testing)")
	upgradeCmd.Flags().BoolVar(&upgradeCheck, "check", false,
		"report the latest release without downloading or replacing")
	upgradeCmd.Flags().BoolVar(&upgradeDryRun, "dry-run", false,
		"download and verify the archive but do not replace the binary")
	upgradeCmd.Flags().BoolVar(&upgradeForce, "force", false,
		"upgrade even when versions match, or override the package-manager guard")
	upgradeCmd.Flags().StringVar(&upgradeVersion, "version", "",
		"pin to a specific release tag (e.g. v0.4.0); default is /releases/latest")
	upgradeCmd.Flags().BoolVar(&upgradeVerbose, "verbose", false,
		"print per-step progress to stderr")
	rootCmd.AddCommand(upgradeCmd)
}
