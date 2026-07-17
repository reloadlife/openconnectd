// Command openconnectd manages ocserv (OpenConnect/AnyConnect SSL VPN) on a
// host and exposes a loopback REST API. The `tui` subcommand opens a terminal
// dashboard against a running daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/reloadlife/openconnectd/internal/config"
	"github.com/reloadlife/openconnectd/internal/httpapi"
	"github.com/reloadlife/openconnectd/internal/metrics"
	"github.com/reloadlife/openconnectd/internal/ocserv"
	"github.com/reloadlife/openconnectd/internal/state"
	"github.com/reloadlife/openconnectd/internal/tui"
)

func main() {
	// Subcommands before flags: `openconnectd tui ...`.
	if len(os.Args) > 1 && os.Args[1] == "tui" {
		if err := runTUI(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "tui:", err)
			os.Exit(1)
		}
		return
	}

	var (
		cfgPath     = flag.String("config", "", "path to openconnectd.yaml")
		listen      = flag.String("listen", "", "override API listen address")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("openconnectd %s (%s)\n", httpapi.Version, httpapi.Commit)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}

	store, err := state.Open(filepath.Join(cfg.StateDir, "state.json"))
	if err != nil {
		log.Error("state", "err", err)
		os.Exit(1)
	}
	mgr := ocserv.NewManager(cfg, store, log)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           httpapi.New(cfg, mgr, log).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Prometheus exporter on its own loopback port.
	var metricsSrv *http.Server
	if cfg.MetricsListen != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", metrics.Handler(mgr))
		metricsSrv = &http.Server{Addr: cfg.MetricsListen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Bring persisted instances back up (best-effort; no-op without ocserv).
	mgr.Reconcile(ctx)

	go func() {
		log.Info("openconnectd listening", "addr", cfg.Listen, "version", httpapi.Version)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("serve", "err", err)
			stop()
		}
	}()
	if metricsSrv != nil {
		go func() {
			log.Info("metrics listening", "addr", cfg.MetricsListen)
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Warn("metrics serve", "err", err)
			}
		}()
	}

	<-ctx.Done()
	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
	if metricsSrv != nil {
		_ = metricsSrv.Shutdown(shutCtx)
	}
}

// runTUI parses the tui subcommand flags and launches the dashboard.
func runTUI(args []string) error {
	fs := flag.NewFlagSet("tui", flag.ExitOnError)
	url := fs.String("url", "http://127.0.0.1:51990", "openconnectd API base URL")
	token := fs.String("token", "", "bearer token (if the daemon requires one)")
	cfgPath := fs.String("config", "", "read url/token from an openconnectd.yaml")
	_ = fs.Parse(args)

	base, tok := *url, *token
	if *cfgPath != "" {
		if c, err := config.Load(*cfgPath); err == nil {
			if c.Listen != "" {
				base = "http://" + c.Listen
			}
			if c.Token != "" {
				tok = c.Token
			}
		}
	}
	return tui.Run(base, tok)
}
