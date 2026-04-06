// Package handler implements the HTTP handlers for the policyguard API.
package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/synesis/policyguard/internal/middleware"
	"github.com/synesis/policyguard/internal/policy"
	pkgerrors "github.com/synesis/policyguard/pkg/errors"
)

// RequestSizeLimit is the maximum allowed body size for evaluation requests.
const RequestSizeLimit = 1 << 20 // 1 MiB

// ─── POST /v1/evaluate ───

type Evaluate struct {
	loader PolicySource
	log    *slog.Logger
}

func NewEvaluate(loader PolicySource, log *slog.Logger) *Evaluate {
	return &Evaluate{loader: loader, log: log}
}

func (h *Evaluate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := h.log.With("request_id", middleware.RequestID(r.Context()))

	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "content-type must be application/json")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, RequestSizeLimit+1))
	if err != nil {
		log.Error("failed to read request body", "error", err)
		writeError(w, http.StatusInternalServerError, pkgerrors.ErrInternal.Error())
		return
	}
	if len(body) > RequestSizeLimit {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}

	var req policy.EvaluationRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, pkgerrors.ErrBadRequest.Error()+": invalid JSON body")
		return
	}

	// Validate required fields.
	if req.ServiceName == "" {
		writeError(w, http.StatusBadRequest, "service_name is required")
		return
	}
	if req.Environment == "" {
		writeError(w, http.StatusBadRequest, "environment is required")
		return
	}
	if req.Image == "" {
		writeError(w, http.StatusBadRequest, "image is required")
		return
	}
	if req.Owner == "" {
		writeError(w, http.StatusBadRequest, "owner is required")
		return
	}

	sets := h.loader.Policies()
	if sets == nil {
		writeError(w, http.StatusServiceUnavailable, pkgerrors.ErrServiceUnready.Error())
		return
	}

	result := policy.Evaluate(req, sets)

	status := http.StatusOK
	if result.Decision == policy.DecisionDeny {
		status = http.StatusUnprocessableEntity
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Error("failed to encode response", pkgerrors.ErrorAttr(err))
	}

	log.Info("evaluation complete",
		"decision", result.Decision,
		"violations", len(result.Violations),
		"warnings", len(result.Warnings),
	)
}

// writeError sends a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  message,
		"status": status,
	})
}
