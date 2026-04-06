package policy

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Loader manages a set of policies that can be hot‑reloaded.
// It is safe for concurrent reads and writes.
type Loader struct {
	path string
	mu   sync.RWMutex
	sets []PolicySet
	log  *slog.Logger
}

// PolicyProvider is the interface that Loader and StubLoader satisfy.
// It is re-exported by callers that need to decouple from the concrete type.
type PolicyProvider interface {
	Policies() []PolicySet
	IsReady() bool
	Reload() error
	StartWatch(ctx context.Context, debounceInterval time.Duration, onReloadComplete func(error)) func()
}

// LoadError wraps a policy load failure for use in the StubLoader.
var _ PolicyProvider = (*StubLoader)(nil)
var _ PolicyProvider = (*Loader)(nil)

// StubLoader is a Loader that never returns policies. Used as fallback when initial load fails.
// Exported so main.go can reference it without importing an internal package.
type StubLoader struct{}

func (s *StubLoader) Policies() []PolicySet { return nil }
func (s *StubLoader) IsReady() bool         { return false }
func (s *StubLoader) Reload() error         { return fmt.Errorf("stub loader: no policies configured") }
func (s *StubLoader) StartWatch(ctx context.Context, _ time.Duration, _ func(error)) func() {
	return func() {}
}

// NewLoader creates a Loader and performs the initial load.
// If the initial load fails, the Loader is returned with an error and no policies.
func NewLoader(path string, log *slog.Logger) (*Loader, error) {
	sets, err := ParseFile(path)
	if err != nil {
		return nil, fmt.Errorf("initial policy load from %s: %w", path, err)
	}

	l := &Loader{
		path: path,
		sets: sets,
		log:  log,
	}
	return l, nil
}

// Policies returns the current policies. Returns nil if not loaded.
func (l *Loader) Policies() []PolicySet {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.sets == nil {
		return nil
	}
	// Return a copy to prevent caller mutation.
	out := make([]PolicySet, len(l.sets))
	copy(out, l.sets)
	return out
}

// IsReady returns true when policies have been loaded successfully.
func (l *Loader) IsReady() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.sets != nil
}

// Reload re‑parses the policy file and atomically swaps the in‑memory set.
// On failure it returns an error and keeps the previous policies intact.
func (l *Loader) Reload() error {
	sets, err := ParseFile(l.path)
	if err != nil {
		l.log.Error("policy reload failed, keeping current policies", "error", err)
		return fmt.Errorf("reload policies from %s: %w", l.path, err)
	}

	l.mu.Lock()
	l.sets = sets
	l.mu.Unlock()

	l.log.Info("policies reloaded successfully", "policy_count", len(sets))
	return nil
}

// StartWatch starts a background goroutine that watches the policy file for changes
// and triggers automatic reloads. Returns a stop function.
// Uses a debounce timer to avoid handling duplicate fsnotify events.
func (l *Loader) StartWatch(ctx context.Context, debounceInterval time.Duration, onReloadComplete func(error)) func() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		l.log.Error("failed to create file watcher", "error", err)
		return func() {}
	}

	// Attempt to watch the policy file directly.
	if err := watcher.Add(l.path); err != nil {
		// Fall back to watching the parent directory.
		// This handles cases where editors do atomic renames.
		l.log.Warn("cannot watch policy file directly, watching parent directory", "path", l.path)
		if parent := parentDir(l.path); parent != "" {
			if err2 := watcher.Add(parent); err2 != nil {
				l.log.Error("failed to watch parent directory", "error", err2)
				return func() {}
			}
		}
	}

	stopCh := make(chan struct{})

	go func() {
		defer func() {
			if err := watcher.Close(); err != nil {
				l.log.Error("failed to close watcher", "error", err)
			}
		}()

		var debounceTimer *time.Timer
		var debounceCh <-chan time.Time

		for {
			select {
			case <-stopCh:
				return
			case <-ctx.Done():
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// Only react to relevant events on our file.
				if !fileMatches(event.Name, l.path) {
					continue
				}
				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
					continue
				}

				l.log.Info("policy file change detected", "event", event.Op.String())

				// Debounce: create or reset the timer on every event.
				if debounceTimer == nil {
					debounceTimer = time.NewTimer(debounceInterval)
					debounceCh = debounceTimer.C
				} else {
					if !debounceTimer.Stop() {
						select {
						case <-debounceTimer.C:
						default:
						}
					}
					debounceTimer.Reset(debounceInterval)
				}

			case <-debounceCh:
				// Debounce interval elapsed — perform reload.
				l.log.Info("triggering policy reload after debounce")
				if err := l.Reload(); onReloadComplete != nil {
					onReloadComplete(err)
				}
				// Reset timer references so the next event starts a new debounce window.
				debounceTimer = nil
				debounceCh = nil

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				l.log.Error("file watcher error", "error", err)
			}
		}
	}()

	return func() {
		close(stopCh)
	}
}

// fileMatches checks if the watch event name matches the tracked policy path.
func fileMatches(eventName, targetPath string) bool {
	return eventName == targetPath
}

// parentDir returns the directory component of a POSIX path.
func parentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return ""
}
