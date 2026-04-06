package policy

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewLoader_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.yaml")
	writePolicy(t, path, validPolicyYAML)

	log := testSlog()
	loader, err := NewLoader(path, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !loader.IsReady() {
		t.Error("loader should be ready after successful load")
	}
	sets := loader.Policies()
	if len(sets) == 0 {
		t.Error("expected policies, got none")
	}
}

func TestNewLoader_Failure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.yaml")

	log := testSlog()
	loader, err := NewLoader(path, log)
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
	if loader != nil {
		t.Error("expected nil loader on failure")
	}
}

func TestLoader_Reload_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.yaml")
	writePolicy(t, path, validPolicyYAML)

	log := testSlog()
	loader, err := NewLoader(path, log)
	if err != nil {
		t.Fatalf("initial load failed: %v", err)
	}

	initialSets := loader.Policies()
	initialLen := len(initialSets)

	// Write a new policy file with additional policies.
	writePolicy(t, path, `policies:
  - name: test-policy
    rules:
      - type: required_labels
        severity: deny
        labels: ["app"]
        description: "must have app label"
  - name: extra
    rules:
      - type: max_cpu
        severity: warn
        value: 2
        description: "extra cpu limit"
`)

	if err := loader.Reload(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	sets := loader.Policies()
	if len(sets) <= initialLen {
		t.Errorf("expected more policies after reload, got %d (was %d)", len(sets), initialLen)
	}
}

func TestLoader_Reload_Failure_KeepsOld(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.yaml")
	writePolicy(t, path, validPolicyYAML)

	log := testSlog()
	loader, err := NewLoader(path, log)
	if err != nil {
		t.Fatalf("initial load failed: %v", err)
	}

	initialSets := loader.Policies()
	initialLen := len(initialSets)

	// Write invalid YAML.
	if err := os.WriteFile(path, []byte("{{{bad yaml\n  - not: valid: yaml: [}"), 0644); err != nil {
		t.Fatalf("write file failed: %v", err)
	}

	err = loader.Reload()
	if err == nil {
		t.Fatal("expected reload to fail with bad YAML")
	}

	// Old policies should still be intact.
	sets := loader.Policies()
	if len(sets) != initialLen {
		t.Errorf("expected %d policies after failed reload, got %d", initialLen, len(sets))
	}
}

func TestLoader_Policies_ReturnsCopy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.yaml")
	writePolicy(t, path, validPolicyYAML)

	log := testSlog()
	loader, err := NewLoader(path, log)
	if err != nil {
		t.Fatalf("initial load failed: %v", err)
	}

	sets1 := loader.Policies()
	sets2 := loader.Policies()

	// Mutate sets1 — should not affect sets2
	if len(sets1) > 0 {
		sets1[0].Name = "mutated"
	}

	if len(sets2) > 0 && sets2[0].Name == "mutated" {
		t.Error("Policies() should return a copy to prevent mutation")
	}
}

func TestLoader_StartWatch_FileChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.yaml")
	writePolicy(t, path, validPolicyYAML)

	log := testSlog()
	loader, err := NewLoader(path, log)
	if err != nil {
		t.Fatalf("initial load failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reloadDone := make(chan error, 1)
	stopWatch := loader.StartWatch(ctx, 200*time.Millisecond, func(err error) {
		reloadDone <- err
	})
	defer stopWatch()

	// Give the watcher time to set up the file watch.
	time.Sleep(300 * time.Millisecond)

	// Write a new policy file.
	writePolicy(t, path, `policies:
  - name: test-policy
    rules:
      - type: required_labels
        severity: deny
        labels: ["app"]
        description: "must have app label"
  - name: new-policy
    rules:
      - type: max_memory
        severity: warn
        value: 1024
        description: "new memory limit"
`)

	// Wait for reload to complete (with generous timeout for fsnotify).
	select {
	case err := <-reloadDone:
		if err != nil {
			t.Fatalf("reload callback error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for file watcher to detect change")
	}

	sets := loader.Policies()
	found := false
	for _, s := range sets {
		if s.Name == "new-policy" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected new-policy to be loaded, got: %v", sets)
	}
}

func TestLoader_StartWatch_BadReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.yaml")
	writePolicy(t, path, validPolicyYAML)

	log := testSlog()
	loader, err := NewLoader(path, log)
	if err != nil {
		t.Fatalf("initial load failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reloadDone := make(chan error, 1)
	stopWatch := loader.StartWatch(ctx, 200*time.Millisecond, func(err error) {
		reloadDone <- err
	})
	defer stopWatch()

	time.Sleep(300 * time.Millisecond)

	// Write bad YAML to trigger a reload failure.
	if err := os.WriteFile(path, []byte(":::invalid:::\n{{{{"), 0644); err != nil {
		t.Fatalf("write file failed: %v", err)
	}

	select {
	case err := <-reloadDone:
		if err == nil {
			t.Fatal("expected reload error callback for bad YAML")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for reload error callback")
	}

	// Loader should still be ready with old policies.
	if !loader.IsReady() {
		t.Error("loader should still be ready after failed reload")
	}
}

func TestLoader_PolicyProvider_Interface(t *testing.T) {
	// Verify Loader satisfies PolicyProvider.
	var _ PolicyProvider = (*Loader)(nil)

	// Verify StubLoader satisfies PolicyProvider.
	var _ PolicyProvider = (*StubLoader)(nil)
}

func TestStubLoader(t *testing.T) {
	stub := &StubLoader{}

	if stub.IsReady() {
		t.Error("StubLoader should never be ready")
	}
	if sets := stub.Policies(); sets != nil {
		t.Errorf("StubLoader should return nil policies, got %v", sets)
	}
	if err := stub.Reload(); err == nil {
		t.Error("StubLoader reload should always fail")
	}
	// Stop function should be a no-op.
	stop := stub.StartWatch(context.Background(), 0, nil)
	stop() // should not panic
}

// ─── Helpers ───

const validPolicyYAML = `policies:
  - name: test-policy
    rules:
      - type: required_labels
        severity: deny
        labels: ["app"]
        description: "must have app label"
`

func writePolicy(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
}

// testSlog returns a discard logger for tests.
func testSlog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
