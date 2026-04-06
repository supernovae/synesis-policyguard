package handler

import (
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/synesis/policyguard/internal/policy"
	pkgerrors "github.com/synesis/policyguard/pkg/errors"
)

type PolicySource interface {
	Policies() []policy.PolicySet
	IsReady() bool
}

// Health handles /healthz and /readyz.
type Health struct {
	loader PolicySource
	log    *slog.Logger
}

// Metrics holds the prometheus metrics for the service.
var Metrics struct {
	EvaluationsTotal *EvaluationCounter
	EvalDuration     *EvaluationDuration
	ReloadsTotal     *ReloadCounter
	PolicyVersion    *PolicyVersionGauge
}

// EvaluationCounter wraps prometheus counter.
type EvaluationCounter struct {
	allow atomic.Int64
	deny  atomic.Int64
	warn  atomic.Int64
}

func (c *EvaluationCounter) IncAllow()    { c.allow.Add(1) }
func (c *EvaluationCounter) IncDeny()     { c.deny.Add(1) }
func (c *EvaluationCounter) IncWarn()     { c.warn.Add(1) }
func (c *EvaluationCounter) Allow() int64 { return c.allow.Load() }
func (c *EvaluationCounter) Deny() int64  { return c.deny.Load() }
func (c *EvaluationCounter) Warn() int64  { return c.warn.Load() }

type EvaluationDuration struct {
	buckets map[string]atomic.Int64
}

func NewEvaluationDuration() *EvaluationDuration {
	return &EvaluationDuration{buckets: make(map[string]atomic.Int64)}
}

type ReloadCounter struct {
	success atomic.Int64
	failed  atomic.Int64
}

func (c *ReloadCounter) IncSuccess()    { c.success.Add(1) }
func (c *ReloadCounter) IncFailed()     { c.failed.Add(1) }
func (c *ReloadCounter) Success() int64 { return c.success.Load() }
func (c *ReloadCounter) Failed() int64  { return c.failed.Load() }

type PolicyVersionGauge struct {
	value atomic.Int64
}

func (c *PolicyVersionGauge) Set(ts int64) { c.value.Store(ts) }
func (c *PolicyVersionGauge) Value() int64 { return c.value.Load() }

func NewHealth(loader PolicySource, log *slog.Logger) *Health {
	Metrics.EvaluationsTotal = &EvaluationCounter{}
	Metrics.EvalDuration = NewEvaluationDuration()
	Metrics.ReloadsTotal = &ReloadCounter{}
	Metrics.PolicyVersion = &PolicyVersionGauge{}
	return &Health{loader: loader, log: log}
}

func (h *Health) Healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (h *Health) Readyz(w http.ResponseWriter, r *http.Request) {
	if h.loader.IsReady() {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
		return
	}
	http.Error(w, pkgerrors.ErrServiceUnready.Error(), http.StatusServiceUnavailable)
}
