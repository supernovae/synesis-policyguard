// Package config defines server configuration loaded from CLI flags and env vars.
package config

import (
	"flag"
	"os"
)

// Config holds the application's runtime configuration.
type Config struct {
	Port       string // HTTP listen port
	PolicyPath string // Path to the policies YAML file or directory
	LogLevel   string // slog level: debug, info, warn, error
}

// Load populates Config from flags with environment variable fallbacks and defaults.
func Load() Config {
	var cfg Config

	flag.StringVar(&cfg.Port, "port", envOr("PORT", "8080"), "HTTP listen port")
	flag.StringVar(&cfg.PolicyPath, "policy-dir", envOr("POLICY_DIR", "configs/policies.yaml"), "Path to policy YAML file")
	flag.StringVar(&cfg.LogLevel, "log-level", envOr("LOG_LEVEL", "info"), "Log level (debug, info, warn, error)")
	flag.Parse()

	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
