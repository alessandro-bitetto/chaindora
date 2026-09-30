package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/alessandro-bitetto/chaindora/internal/server"
)

// `chdora server` — multi-machine fleet mode. Opt-in, off
// by default. Single binary, single JSON state file. Suitable
// for tens-to-hundreds of agents; for larger fleets the
// server's storage layer should move to SQL — that's .

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Fleet-mode HTTP server: ingest scans from agents, serve dashboard",
	Long: `chdora server runs a small HTTP service that:

  - accepts findings from many chdora agents (POST /api/v1/agents/<id>/scan)
  - persists them to <data-dir>/state.json (one-file JSON state)
  - serves a dashboard at GET / and a JSON API at /api/v1/*

Deployment posture: stick a TLS-terminating reverse proxy in
front of this (nginx / caddy / Cloudflare Tunnel). The server
itself doesn't speak TLS. It binds to loopback by default. Agent enrollment
is disabled without --enrollment-secret. Dashboard/API reads require an
independent operator token, generated in <data-dir>/read-token (mode 0600)
or supplied with --read-token-file. In the browser use username viewer and
the file's contents as password. API clients use Authorization: Bearer <token>.

Quick start:

  # On the server box
  chdora server start --addr 127.0.0.1:8080 --data-dir /var/lib/chdora --enrollment-secret SOME-LONG-RANDOM

  # On each agent
  chdora agent enroll --server https://fleet.example.com \
                       --name laptop-alice \
                       --enrollment-secret SOME-LONG-RANDOM
  chdora agent push   --findings ./findings.json
  # Or hook into watch:
  chdora watch --server https://fleet.example.com`,
}

var (
	serverAddr             string
	serverDataDir          string
	serverEnrollmentSecret string
	serverReadTokenFile    string
	serverReadTimeout      time.Duration
	serverWriteTimeout     time.Duration
)

var serverStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the fleet HTTP server",
	RunE: func(cmd *cobra.Command, args []string) error {
		if serverDataDir == "" {
			home, _ := os.UserHomeDir()
			serverDataDir = filepath.Join(home, ".chaindora", "server")
		}
		statePath := filepath.Join(serverDataDir, "state.json")
		store, err := server.NewStore(statePath)
		if err != nil {
			return fmt.Errorf("open store: %w", err)
		}
		srv := server.New(store, serverEnrollmentSecret, Version)
		tokenPath := serverReadTokenFile
		if tokenPath == "" {
			tokenPath = filepath.Join(serverDataDir, "read-token")
		}
		srv.ReadToken, err = loadServerReadToken(tokenPath, serverReadTokenFile == "")
		if err != nil {
			return fmt.Errorf("fleet read credential: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[chdora server] dashboard username: viewer; password file: %s\n", tokenPath)

		httpSrv := &http.Server{
			Addr:         serverAddr,
			Handler:      srv.Handler(),
			ReadTimeout:  serverReadTimeout,
			WriteTimeout: serverWriteTimeout,
		}

		fmt.Fprintf(os.Stderr, "[chdora server] listening on %s\n", serverAddr)
		fmt.Fprintf(os.Stderr, "[chdora server] data dir %s\n", serverDataDir)
		if serverEnrollmentSecret == "" {
			fmt.Fprintln(os.Stderr, "[chdora server] agent enrollment disabled: configure --enrollment-secret to enable")
		}

		// Graceful shutdown: flush state on SIGTERM / SIGINT.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		errCh := make(chan error, 1)
		go func() {
			if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "[chdora server] shutting down — flushing state")
			shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := httpSrv.Shutdown(shutCtx); err != nil {
				fmt.Fprintf(os.Stderr, "warn: shutdown: %v\n", err)
			}
			if err := store.Flush(); err != nil {
				fmt.Fprintf(os.Stderr, "warn: state flush: %v\n", err)
			}
			return nil
		}
	},
}

func init() {
	serverStartCmd.Flags().StringVar(&serverAddr, "addr", "127.0.0.1:8080", "address to listen on (host:port)")
	serverStartCmd.Flags().StringVar(&serverReadTokenFile, "read-token-file", "", "operator token file (default: generate a private read-token file in the data directory)")
	serverStartCmd.Flags().StringVar(&serverDataDir, "data-dir", "", "directory for state.json (default: ~/.chaindora/server)")
	serverStartCmd.Flags().StringVar(&serverEnrollmentSecret, "enrollment-secret", "", "shared secret agents must present to enroll; empty disables enrollment")
	serverStartCmd.Flags().DurationVar(&serverReadTimeout, "read-timeout", 30*time.Second, "HTTP read timeout per request")
	serverStartCmd.Flags().DurationVar(&serverWriteTimeout, "write-timeout", 30*time.Second, "HTTP write timeout per request")
	serverCmd.AddCommand(serverStartCmd)
	rootCmd.AddCommand(serverCmd)
}
