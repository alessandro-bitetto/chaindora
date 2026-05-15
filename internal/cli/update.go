package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	defaultUpdateSource = "https://api.github.com/repos/alessandro-bitetto/chaindora/contents/incidents?ref=main"
	updateUserAgent     = "chdora-update/"
)

var (
	updateSource  string
	updateDest    string
	updateDryRun  bool
	updateVerbose bool
)

// githubContentEntry is the subset of the GitHub Contents API response we use.
// Full schema: https://docs.github.com/en/rest/repos/contents
type githubContentEntry struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Type        string `json:"type"`
	Size        int    `json:"size"`
	DownloadURL string `json:"download_url"`
	SHA         string `json:"sha"`
}

type updateMeta struct {
	LastUpdated string `json:"last_updated"`
	Source      string `json:"source"`
	FileCount   int    `json:"file_count"`
	Tool        string `json:"tool"`
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Refresh the curated incident pack from the upstream repo",
	Long: `Fetches the latest incident-pack YAML files from the official
chaindora repo into ~/.chaindora/incidents/ (or the directory passed via
--dest).

Without periodic updates, chdora only knows about the incidents that
existed in main at the time the binary was installed. Run this command
after every reported supply-chain attack against an ecosystem you use.

The default --source uses GitHub's Contents API; --source can be pointed
at any compatible directory-listing endpoint to fetch from a fork or a
private incident pack.`,
	RunE: runUpdate,
}

func runUpdate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	dest, err := resolveUpdateDest(updateDest)
	if err != nil {
		return err
	}
	if !updateDryRun {
		if err := os.MkdirAll(dest, 0o755); err != nil {
			return fmt.Errorf("create dest: %w", err)
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}

	files, err := fetchIncidentListing(ctx, client, updateSource)
	if err != nil {
		return fmt.Errorf("list upstream %s: %w", updateSource, err)
	}

	var added, updated, unchanged, skipped int
	for _, f := range files {
		if f.Type != "file" || !isYAMLName(f.Name) {
			continue
		}
		body, err := fetchUpdateFile(ctx, client, f.DownloadURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skip %s: %v\n", f.Name, err)
			skipped++
			continue
		}
		if !validateIncidentYAML(body) {
			fmt.Fprintf(os.Stderr, "warn: skip %s: not a valid incident YAML\n", f.Name)
			skipped++
			continue
		}
		destPath := filepath.Join(dest, f.Name)
		status, err := writeIfChanged(destPath, body, updateDryRun)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: write %s: %v\n", f.Name, err)
			skipped++
			continue
		}
		switch status {
		case "added":
			added++
		case "updated":
			updated++
		case "unchanged":
			unchanged++
		}
		if updateVerbose {
			fmt.Fprintf(os.Stderr, "%s %s\n", status, f.Name)
		}
	}

	if !updateDryRun {
		writeUpdateMeta(dest, updateSource, added+updated+unchanged)
	}

	verb := "fetched"
	if updateDryRun {
		verb = "would fetch"
	}
	fmt.Printf("%s %d incidents (%d added, %d updated, %d unchanged, %d skipped) into %s\n",
		verb, added+updated+unchanged, added, updated, unchanged, skipped, dest)
	return nil
}

func resolveUpdateDest(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home: %w", err)
	}
	return filepath.Join(home, ".chaindora", "incidents"), nil
}

func fetchIncidentListing(ctx context.Context, client *http.Client, url string) ([]githubContentEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", updateUserAgent+Version)
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
	var entries []githubContentEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode listing: %w", err)
	}
	return entries, nil
}

func fetchUpdateFile(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	if url == "" {
		return nil, fmt.Errorf("empty download_url")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", updateUserAgent+Version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	// 1 MiB cap protects against a misconfigured / malicious source.
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func validateIncidentYAML(data []byte) bool {
	var inc struct {
		ID string `yaml:"id"`
	}
	if err := yaml.Unmarshal(data, &inc); err != nil {
		return false
	}
	return strings.TrimSpace(inc.ID) != ""
}

func isYAMLName(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}

// writeIfChanged compares existing content (if any) against body; only writes
// when they differ. Atomic via tmp + rename. Returns "added", "updated", or
// "unchanged".
func writeIfChanged(path string, body []byte, dryRun bool) (string, error) {
	existing, err := os.ReadFile(path)
	status := "added"
	if err == nil {
		if bytes.Equal(existing, body) {
			return "unchanged", nil
		}
		status = "updated"
	}
	if dryRun {
		return status, nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return status, nil
}

func writeUpdateMeta(dest, source string, fileCount int) {
	meta := updateMeta{
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
		Source:      source,
		FileCount:   fileCount,
		Tool:        "chdora/" + Version,
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dest, ".meta.json"), data, 0o644)
}

func init() {
	updateCmd.Flags().StringVar(&updateSource, "source", defaultUpdateSource,
		"GitHub Contents API URL for the incidents directory")
	updateCmd.Flags().StringVar(&updateDest, "dest", "",
		"destination directory (default: ~/.chaindora/incidents)")
	updateCmd.Flags().BoolVar(&updateDryRun, "dry-run", false,
		"report what would change without writing")
	updateCmd.Flags().BoolVar(&updateVerbose, "verbose", false,
		"print per-file status to stderr")
	rootCmd.AddCommand(updateCmd)
}
