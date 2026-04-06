// Package log provides a structured logger backed by log/slog.
package log

import (
	"log/slog"
	"os"
)

// NewLogger returns a *slog.Logger at the given level with JSON output.
func NewLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	return slog.New(newJSONHandler(os.Stderr, opts))
}

// newJSONHandler wraps slog's JSON handler.
// Keeping it separate so we can swap implementations if needed.
func newJSONHandler(w *os.File, opts *slog.HandlerOptions) slog.Handler {
	return slog.NewJSONHandler(w, opts)
}

// Attrs helper
func ErrorAttr(err error) slog.Attr {
	return slog.String("error", err.Error())
}

// Attr returns a generic slog.Attr from key-value pairs.
func Attr(key string, value interface{}) slog.Attr {
	switch v := value.(type) {
	case string:
		return slog.String(key, v)
	case int:
		return slog.Int(key, v)
	case int64:
		return slog.Int64(key, v)
	case float64:
		return slog.Float64(key, v)
	case bool:
		return slog.Bool(key, v)
	case error:
		return slog.String(key, v.Error())
	default:
		return slog.Any(key, value)
	}
}

// MustLevel validates and returns a canonical log level string.
func MustLevel(level string) string {
	switch level {
	case "debug", "info", "warn", "error":
		return level
	}
	return "info"
}
