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

// `chdora server` — v0.13 multi-machine fleet mode. Opt-in, off
// by default. Single binary, single JSON state file. Suitable
// for tens-to-hundreds of agents; for larger fleets the
// server's storage layer should move to SQL — that's v0.14+.

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Fleet-mode HTTP server: ingest scans from agents, serve dashboard",
	Long: `chdora server runs a small HTTP service that:

  - accepts findings from many chdora agents (POST /api/v1/agents/<id>/scan)
  - persists them to <data-dir>/state.json (one-file JSON state)
  - serves a dashboard at GET / and a JSON API at /api/v1/*

Deployment posture: stick a TLS-terminating reverse proxy in
front of this (nginx / caddy / Cloudflare Tunnel). The server
itself doesn't speak TLS in v0.13.0 — set --enrollment-secret
and run the listener on a private interface.

Quick start:

  # On the server box
  chdora server start --addr :8080 --data-dir /var/lib/chdora --enrollment-secret SOME-LONG-RANDOM

  # On each agent
  chdora agent enroll --server http://server:8080 \
                       --name laptop-alice \
                       --enrollment-secret SOME-LONG-RANDOM
  chdora agent push   --findings ./findings.json
  # Or hook into watch:
  chdora watch --server http://server:8080`,
}

var (
	serverAddr             string
	serverDataDir          string
	serverEnrollmentSecret string
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

		httpSrv := &http.Server{
			Addr:         serverAddr,
			Handler:      srv.Handler(),
			ReadTimeout:  serverReadTimeout,
			WriteTimeout: serverWriteTimeout,
		}

		fmt.Fprintf(os.Stderr, "[chdora server] listening on %s\n", serverAddr)
		fmt.Fprintf(os.Stderr, "[chdora server] data dir %s\n", serverDataDir)
		if serverEnrollmentSecret == "" {
			fmt.Fprintln(os.Stderr, "[chdora server] WARNING: no --enrollment-secret — anyone with network access can enroll a fake agent")
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
	serverStartCmd.Flags().StringVar(&serverAddr, "addr", ":8080", "address to listen on (host:port)")
	serverStartCmd.Flags().StringVar(&serverDataDir, "data-dir", "", "directory for state.json (default: ~/.chaindora/server)")
	serverStartCmd.Flags().StringVar(&serverEnrollmentSecret, "enrollment-secret", "", "shared secret agents must present in X-Chaindora-Enroll-Secret to enroll. Empty = open enrollment (only safe for closed networks).")
	serverStartCmd.Flags().DurationVar(&serverReadTimeout, "read-timeout", 30*time.Second, "HTTP read timeout per request")
	serverStartCmd.Flags().DurationVar(&serverWriteTimeout, "write-timeout", 30*time.Second, "HTTP write timeout per request")
	serverCmd.AddCommand(serverStartCmd)
	rootCmd.AddCommand(serverCmd)
}
