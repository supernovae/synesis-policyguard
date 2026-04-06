package api

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/synesis/policyguard/internal/api/handler"
	"github.com/synesis/policyguard/internal/middleware"
	"github.com/synesis/policyguard/internal/policy"
	pkgerrors "github.com/synesis/policyguard/pkg/errors"
)

// PolicySource abstracts policy loading for the server.
type PolicySource interface {
	Policies() []policy.PolicySet
	IsReady() bool
}

// Server encapsulates the HTTP server lifecycle.
type Server struct {
	addr    string
	httpSrv *http.Server
	log     *slog.Logger
	loader  PolicySource
}

// NewServer wires handlers and returns a Server ready to start.
func NewServer(addr string, loader PolicySource, log *slog.Logger) *Server {
	mux := http.NewServeMux()

	healthHandler := handler.NewHealth(loader, log)
	evalHandler := handler.NewEvaluate(loader, log)

	// Go 1.22+ method-anchored routes.
	mux.HandleFunc("GET /healthz", healthHandler.Healthz)
	mux.HandleFunc("GET /readyz", healthHandler.Readyz)
	mux.HandleFunc("POST /v1/evaluate", evalHandler.ServeHTTP)
	mux.Handle("GET /metrics", promhttp.Handler())

	// Middleware: wrap with request logging and request ID injection.
	wrapped := middleware.RequestMiddleware(withRequestLogging(mux, log))

	return &Server{
		addr: addr,
		httpSrv: &http.Server{
			Addr:              addr,
			Handler:           wrapped,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
		},
		log:    log,
		loader: loader,
	}
}

// Start begins serving in a goroutine and returns immediately.
func (s *Server) Start() error {
	s.log.Info("starting HTTP server", "addr", s.addr)
	go func() {
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Error("HTTP server failed", pkgerrors.ErrorAttr(err))
			os.Exit(1)
		}
	}()
	return nil
}

// Shutdown performs a graceful shutdown with context timeout.
func (s *Server) Shutdown(ctx context.Context) error {
	s.log.Info("shutting down HTTP server")
	shutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.httpSrv.Shutdown(shutCtx)
}

// ─── Middleware ───

func withRequestLogging(next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		defer func() {
			elapsed := time.Since(start)
			log.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.statusCode,
				"duration_ms", elapsed.Milliseconds(),
			)
		}()

		next.ServeHTTP(wrapped, r)
	})
}

// ─── Middleware ───.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
