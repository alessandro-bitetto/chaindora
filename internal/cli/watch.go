package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// `chdora watch` is the continuous-protection complement to
// `chdora gate`. The gate stops new bad bytes from arriving; watch
// catches the case where a package was clean when installed but
// later got reported in OSV/MAL-* (the sleeper class).
//
// Mode of operation:
//
//  1. Periodically (default 1 hour) re-runs the audit flow.
//  2. Compares the current finding set against the previous run's
//     state stored at ~/.chaindora/watch-state.json.
//  3. For every NEW finding (fingerprint not in prior state),
//     emits a line on stdout AND optionally POSTs to a configured
//     webhook URL. Findings that have disappeared since the prior
//     run (the package was uninstalled / upgraded) are also
//     reported so the user gets a complete delta.
//  4. Updates the state and sleeps.
//
// Survives across restarts because the state lives on disk. SIGHUP
// triggers an immediate re-scan; SIGTERM / SIGINT exits cleanly.

var (
	watchInterval   time.Duration
	watchWebhookURL string
	watchOnce       bool
	watchStatePath  string
	watchSkipOSV    bool
	watchVerbose    bool
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Continuously re-scan the host inventory and alert on new findings",
	Long: `Long-running command. Re-scans the host's installed packages and
project trees on a schedule and alerts when a NEW finding lands —
typically because OSV/MAL-* added an entry for something already
on disk.

  chdora watch                              # once an hour, log to stdout
  chdora watch --interval 15m
  chdora watch --webhook https://example.com/chaindora
  chdora watch --once                       # single pass; good for cron
  chdora watch --interval 24h --webhook ... # daily, alert via slack/discord webhook

The webhook POSTs a JSON body:

  {
    "event": "new-finding",
    "host": "<hostname>",
    "chdora_version": "0.10.0",
    "scanned_at": "2026-05-15T22:00:00Z",
    "finding": { ... full Finding object ... }
  }

State persists at ~/.chaindora/watch-state.json (override with
--state). Delete the state file to reset the baseline.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		statePath := watchStatePath
		if statePath == "" {
			home, _ := os.UserHomeDir()
			statePath = filepath.Join(home, ".chaindora", "watch-state.json")
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		// SIGHUP triggers an immediate re-scan. Buffered so we
		// don't drop signals while a scan is in progress.
		reload := make(chan os.Signal, 1)
		signal.Notify(reload, syscall.SIGHUP)

		fmt.Fprintf(os.Stderr, "[chdora watch] state at %s; interval %s; webhook=%s\n",
			statePath, watchInterval, redactWebhook(watchWebhookURL))

		for {
			if err := watchOnePass(ctx, statePath); err != nil {
				if errors.Is(err, context.Canceled) {
					fmt.Fprintln(os.Stderr, "[chdora watch] shutting down cleanly")
					return nil
				}
				fmt.Fprintf(os.Stderr, "[chdora watch] pass failed: %v\n", err)
			}
			if watchOnce {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			case <-reload:
				fmt.Fprintln(os.Stderr, "[chdora watch] SIGHUP — re-scanning immediately")
				continue
			case <-time.After(watchInterval):
				continue
			}
		}
	},
}

// watchOnePass runs one detection cycle: scan → diff against
// state → emit deltas → save state.
func watchOnePass(ctx context.Context, statePath string) error {
	prev, err := loadWatchState(statePath)
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}
	fs, err := watchRunAudit(ctx)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	// Compute the deltas.
	currentSet := make(map[string]findings.Finding, len(fs))
	for _, f := range fs {
		currentSet[findings.Fingerprint(f)] = f
	}
	prevSet := prev.fingerprintMap()

	var newFindings []findings.Finding
	for fp, f := range currentSet {
		if _, ok := prevSet[fp]; !ok {
			newFindings = append(newFindings, f)
		}
	}
	var resolvedFps []string
	for fp := range prevSet {
		if _, ok := currentSet[fp]; !ok {
			resolvedFps = append(resolvedFps, fp)
		}
	}

	now := time.Now().UTC()
	host, _ := os.Hostname()

	for _, f := range newFindings {
		fmt.Fprintf(os.Stdout, "[%s] new finding: [%s] [%s] %s @ %s — %s\n",
			now.Format(time.RFC3339), f.Severity, f.Detector,
			f.VulnID, f.PURL, f.Summary)
		if watchWebhookURL != "" {
			if err := watchPostWebhook(ctx, watchWebhookURL, watchWebhookEvent{
				Event:         "new-finding",
				Host:          host,
				ChdoraVersion: Version,
				ScannedAt:     now,
				Finding:       f,
			}); err != nil {
				fmt.Fprintf(os.Stderr, "[chdora watch] webhook delivery failed: %v\n", err)
			}
		}
	}
	// v0.13: if a chdora-server is configured (--server URL or
	// the agent is enrolled), push the FULL current state on
	// every pass. The server's own dedup handles "we've seen
	// this fingerprint before" — clients don't need a separate
	// delta protocol.
	if c, _ := loadAgentConfig(agentConfigPath); c != nil && c.ServerURL != "" {
		// watch passes are always intended to be complete scans —
		// any error would have aborted the pass before this push
		// site. Send a complete summary so the server can tell
		// us apart from older agents (no summary = back-compat
		// default of complete on the receiver, but explicit is
		// better than implicit).
		passSummary := findings.NewCompleteSummary(now, len(fs), strings.Join(os.Args, " "), Version)
		if _, err := pushFindingsToServer(c, fs, strings.Join(os.Args, " "), &passSummary); err != nil {
			fmt.Fprintf(os.Stderr, "[chdora watch] server push failed: %v\n", err)
		} else if watchVerbose {
			fmt.Fprintf(os.Stderr, "[chdora watch] pushed %d finding(s) to %s\n", len(fs), c.ServerURL)
		}
	}
	if watchVerbose {
		fmt.Fprintf(os.Stderr, "[chdora watch] pass: scanned %d finding(s); %d new; %d resolved\n",
			len(fs), len(newFindings), len(resolvedFps))
	} else if len(newFindings) == 0 && len(resolvedFps) == 0 && prev.LastScannedAt != "" {
		// Only emit "no change" line when this isn't the first
		// pass — the first pass is always 100% delta.
		fmt.Fprintf(os.Stderr, "[%s] no change since previous pass (%d findings)\n",
			now.Format(time.RFC3339), len(fs))
	}

	// Persist current state.
	newState := watchState{
		LastScannedAt: now.Format(time.RFC3339),
		ChdoraVersion: Version,
		Fingerprints:  make([]string, 0, len(currentSet)),
	}
	for fp := range currentSet {
		newState.Fingerprints = append(newState.Fingerprints, fp)
	}
	return saveWatchState(statePath, &newState)
}

// watchRunAudit produces the inventory for one watch pass.
// Runs the same detector layers the scan command uses
// (osvioc + incident-pack + heuristic) against the host's home
// directory, returning the union of findings. We avoid the
// stdout-rendering path used by `chdora audit` so this stays
// in-process.
//
// Scope deliberately narrower than `chdora audit --whole-machine`:
// watch is meant to run continuously, so we focus on what's
// most likely to produce NEW findings between passes —
// project-level dependency CVEs and incident-pack matches under
// $HOME. Host-state (credential drift, persistence) is better
// suited to an explicit `chdora audit` invocation.
func watchRunAudit(ctx context.Context) ([]findings.Finding, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home: %w", err)
	}
	all, err := watchScanProjects(ctx, home)
	if err != nil {
		return nil, err
	}
	if watchSkipOSV {
		// Drop OSV findings if user opted out — typical for
		// air-gapped watch runs.
		kept := make([]findings.Finding, 0, len(all))
		for _, f := range all {
			if f.Detector != "osv-ioc" {
				kept = append(kept, f)
			}
		}
		all = kept
	}
	return all, nil
}

// watchScanProjects walks $HOME for project manifests and runs
// the scan-projects pipeline against each. Returns the union of
// findings. Errors per-project are logged to stderr and don't
// abort the whole pass — we'd rather report SOME findings than
// none.
func watchScanProjects(ctx context.Context, root string) ([]findings.Finding, error) {
	roots := discoverProjects(root, mergeExcludeMap(nil), false)
	npm, pypi := buildRegistryProbes(false)
	opts := projectScanOpts{
		SkipOSV:       watchSkipOSV,
		SkipIncidents: false,
		SkipHeuristic: false,
		FreshPopular:  false,
		Verbose:       false,
		NPMProbe:      npm,
		PyPIProbe:     pypi,
	}
	var all []findings.Finding
	for _, r := range roots {
		if ctx.Err() != nil {
			return all, ctx.Err()
		}
		fs, err := scanProject(ctx, r, opts)
		if err != nil {
			if watchVerbose {
				fmt.Fprintf(os.Stderr, "[chdora watch] warn: %s: %v\n", r, err)
			}
			continue
		}
		all = append(all, fs...)
	}
	return all, nil
}

// watchState is the persisted shape on disk.
type watchState struct {
	ChdoraVersion string   `json:"chdora_version"`
	LastScannedAt string   `json:"last_scanned_at"`
	Fingerprints  []string `json:"fingerprints"`
}

func (s *watchState) fingerprintMap() map[string]struct{} {
	out := make(map[string]struct{}, len(s.Fingerprints))
	for _, fp := range s.Fingerprints {
		out[fp] = struct{}{}
	}
	return out
}

func loadWatchState(path string) (*watchState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &watchState{}, nil
		}
		return nil, err
	}
	var s watchState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func saveWatchState(path string, s *watchState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".watch-state-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

// watchWebhookEvent is the JSON shape POSTed to the configured
// webhook URL. Stable schema — downstream automation can depend
// on it.
type watchWebhookEvent struct {
	Event         string           `json:"event"`
	Host          string           `json:"host"`
	ChdoraVersion string           `json:"chdora_version"`
	ScannedAt     time.Time        `json:"scanned_at"`
	Finding       findings.Finding `json:"finding"`
}

func watchPostWebhook(ctx context.Context, url string, evt watchWebhookEvent) error {
	body, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "chdora-watch/"+Version)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// redactWebhook scrubs credentials (basic-auth or query-string
// secrets) from the URL we log on startup. Don't reveal token in
// a process listing or shared terminal.
func redactWebhook(u string) string {
	if u == "" {
		return "<none>"
	}
	if i := strings.Index(u, "@"); i > 0 {
		if j := strings.Index(u, "://"); j > 0 && j < i {
			return u[:j+3] + "<redacted>@" + u[i+1:]
		}
	}
	if i := strings.Index(u, "?"); i > 0 {
		return u[:i] + "?<query-redacted>"
	}
	return u
}

func init() {
	watchCmd.Flags().DurationVar(&watchInterval, "interval", 1*time.Hour, "how often to re-scan (e.g. 15m, 1h, 24h)")
	watchCmd.Flags().StringVar(&watchWebhookURL, "webhook", "", "POST new-finding events to this URL")
	watchCmd.Flags().BoolVar(&watchOnce, "once", false, "single pass and exit (use under cron / systemd timer instead of long-running)")
	watchCmd.Flags().StringVar(&watchStatePath, "state", "", "state file path (default: ~/.chaindora/watch-state.json)")
	watchCmd.Flags().BoolVar(&watchSkipOSV, "skip-osv", false, "skip OSV.dev queries (rare; OSV is the whole point of watch)")
	watchCmd.Flags().BoolVar(&watchVerbose, "verbose", false, "log every pass even when nothing changed")
	rootCmd.AddCommand(watchCmd)
}
