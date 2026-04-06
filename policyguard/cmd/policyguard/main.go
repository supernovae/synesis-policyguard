// Main entrypoint for the policyguard service.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/synesis/policyguard/internal/api"
	"github.com/synesis/policyguard/internal/config"
	pglog "github.com/synesis/policyguard/internal/log"
	"github.com/synesis/policyguard/internal/policy"
	pkgerrors "github.com/synesis/policyguard/pkg/errors"
)

func main() {
	cfg := config.Load()
	log := pglog.NewLogger(pglog.MustLevel(cfg.LogLevel))
	slog.SetDefault(log)

	log.Info("policyguard starting",
		"port", cfg.Port,
		"policy_path", cfg.PolicyPath,
		"log_level", cfg.LogLevel,
	)

	// 1. Load policies.
	var provider policy.PolicyProvider
	provider, err := policy.NewLoader(cfg.PolicyPath, log)
	if err != nil {
		// Non-fatal: service starts without policies and reports not-ready.
		log.Error("initial policy load failed — service will start unready", pkgerrors.ErrorAttr(err))
		// Create a stub loader so the server can still handle health endpoints.
		provider = &policy.StubLoader{}
	}

	// 2. Start file watching for hot reload.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stopWatch := provider.StartWatch(ctx, 200*time.Millisecond, func(reloadErr error) {
		if reloadErr != nil {
			log.Error("hot reload failed", pkgerrors.ErrorAttr(reloadErr))
		} else {
			log.Info("hot reload completed")
		}
	})
	defer stopWatch()

	// 3. Start HTTP server.
	addr := fmt.Sprintf(":%s", cfg.Port)
	srv := api.NewServer(addr, provider, log)
	if err := srv.Start(); err != nil {
		log.Error("HTTP server failed to start", pkgerrors.ErrorAttr(err))
		os.Exit(1)
	}

	// 4. Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Info("received signal, shutting down", "signal", sig.String())

	// 5. Graceful shutdown.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown failed", pkgerrors.ErrorAttr(err))
	}

	log.Info("policyguard stopped")
}
