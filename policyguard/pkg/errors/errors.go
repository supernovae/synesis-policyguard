// Package pkgerrors defines sentinel errors for the policyguard error taxonomy.
package pkgerrors

import (
	"errors"
	"log/slog"
)

// Sentinel errors.
var (
	ErrBadRequest       = errors.New("bad request: invalid input")
	ErrPolicyParse      = errors.New("policy parse error: invalid policy definition")
	ErrInternal         = errors.New("internal server error")
	ErrServiceUnready   = errors.New("service not ready: policies not loaded")
	ErrEvaluationDenied = errors.New("evaluation denied: one or more rules violated")
)

// Classify returns a human-friendly category string for an error.
func Classify(err error) string {
	switch {
	case errors.Is(err, ErrBadRequest):
		return "validation_error"
	case errors.Is(err, ErrPolicyParse):
		return "policy_config_error"
	case errors.Is(err, ErrServiceUnready):
		return "service_unavailable"
	case errors.Is(err, ErrEvaluationDenied):
		return "policy_denied"
	default:
		return "internal_error"
	}
}

// ErrorAttr returns an slog.Attr for use in structured logging with an error.
func ErrorAttr(err error) slog.Attr {
	if err == nil {
		return slog.String("error", "")
	}
	return slog.String("error", err.Error())
}
