package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/synesis/policyguard/internal/policy"
)

// ─── Stub policy source for tests ───

type stubPolicySource struct {
	ready    bool
	policies []policy.PolicySet
}

func (s *stubPolicySource) Policies() []policy.PolicySet { return s.policies }
func (s *stubPolicySource) IsReady() bool                { return s.ready }

// ─── Health endpoint tests ───

func TestHealth_Healthz(t *testing.T) {
	src := &stubPolicySource{ready: false}
	h := NewHealth(src, testLogger(t))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.Healthz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("healthz: got status %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if body != "ok" {
		t.Errorf("healthz: got body %q, want %q", body, "ok")
	}
}

func TestHealth_Readyz_Ready(t *testing.T) {
	src := &stubPolicySource{ready: true}
	h := NewHealth(src, testLogger(t))

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	h.Readyz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("readyz (ready): got status %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if body != "ready" {
		t.Errorf("readyz (ready): got body %q, want %q", body, "ready")
	}
}

func TestHealth_Readyz_NotReady(t *testing.T) {
	src := &stubPolicySource{ready: false}
	h := NewHealth(src, testLogger(t))

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	h.Readyz(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz (not ready): got status %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

// ─── Evaluate endpoint tests ───

func TestEvaluate_Allow(t *testing.T) {
	src := &stubPolicySource{
		ready: true,
		policies: []policy.PolicySet{
			{
				Name: "test",
				Rules: []policy.Rule{
					{Type: policy.RuleTypeRequiredLabels, Severity: policy.SeverityDeny, Labels: []string{"app"}, Description: "must have app"},
				},
			},
		},
	}
	h := NewEvaluate(src, testLogger(t))

	payload := map[string]interface{}{
		"service_name": "my-svc",
		"environment":  "production",
		"image":        "reg.io/app:v1",
		"owner":        "team-a",
		"cpu":          2,
		"memory":       4096,
		"replicas":     3,
		"labels":       map[string]string{"app": "my-svc"},
	}

	w := httptest.NewRecorder()
	w.Body.Reset()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", jsonBody(t, payload))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", w.Code, http.StatusOK)
	}

	var result policy.EvaluationResult
	decodeBody(t, w.Body, &result)

	if result.Decision != policy.DecisionAllow {
		t.Errorf("got decision %s, want %s", result.Decision, policy.DecisionAllow)
	}
}

func TestEvaluate_Deny(t *testing.T) {
	src := &stubPolicySource{
		ready: true,
		policies: []policy.PolicySet{
			{
				Name: "security",
				Rules: []policy.Rule{
					{Type: policy.RuleTypeRequiredLabels, Severity: policy.SeverityDeny, Labels: []string{"app", "team"}, Description: "labels required"},
				},
			},
		},
	}
	h := NewEvaluate(src, testLogger(t))

	payload := map[string]interface{}{
		"service_name": "my-svc",
		"environment":  "production",
		"image":        "reg.io/app:v1",
		"owner":        "team-a",
		"labels":       map[string]string{"app": "svc"}, // missing "team"
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", jsonBody(t, payload))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("got status %d, want %d", w.Code, http.StatusUnprocessableEntity)
	}

	var result policy.EvaluationResult
	decodeBody(t, w.Body, &result)

	if result.Decision != policy.DecisionDeny {
		t.Errorf("got decision %s, want %s", result.Decision, policy.DecisionDeny)
	}
	if len(result.Violations) == 0 {
		t.Error("expected violations for denied request")
	}
}

func TestEvaluate_ServiceUnavailable(t *testing.T) {
	src := &stubPolicySource{ready: false}
	h := NewEvaluate(src, testLogger(t))

	payload := map[string]interface{}{
		"service_name": "svc",
		"environment":  "dev",
		"image":        "reg.io/app:v1",
		"owner":        "team",
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", jsonBody(t, payload))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestEvaluate_MissingRequiredFields(t *testing.T) {
	src := &stubPolicySource{ready: true}
	h := NewEvaluate(src, testLogger(t))

	tests := []struct {
		name    string
		payload map[string]interface{}
	}{
		{"missing service_name", map[string]interface{}{"environment": "dev", "image": "reg.io/app:v1", "owner": "team"}},
		{"missing environment", map[string]interface{}{"service_name": "svc", "image": "reg.io/app:v1", "owner": "team"}},
		{"missing image", map[string]interface{}{"service_name": "svc", "environment": "dev", "owner": "team"}},
		{"missing owner", map[string]interface{}{"service_name": "svc", "environment": "dev", "image": "reg.io/app:v1"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", jsonBody(t, tc.payload))
			req.Header.Set("Content-Type", "application/json")
			h.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("got status %d, want %d", w.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestEvaluate_InvalidJSON(t *testing.T) {
	src := &stubPolicySource{ready: true}
	h := NewEvaluate(src, testLogger(t))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", bytes.NewReader([]byte(`{invalid json`)))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestEvaluate_WrongContentType(t *testing.T) {
	src := &stubPolicySource{ready: true}
	h := NewEvaluate(src, testLogger(t))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "text/plain")
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("got status %d, want %d", w.Code, http.StatusUnsupportedMediaType)
	}
}

func TestEvaluate_BodyTooLarge(t *testing.T) {
	src := &stubPolicySource{ready: true}
	h := NewEvaluate(src, testLogger(t))

	// Create a body just over the limit.
	large := bytes.Repeat([]byte("x"), RequestSizeLimit+1)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", bytes.NewReader(large))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got status %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestEvaluate_NoPolicies(t *testing.T) {
	src := &stubPolicySource{
		ready:    true,
		policies: []policy.PolicySet{}, // non-nil but empty
	}
	h := NewEvaluate(src, testLogger(t))

	payload := map[string]interface{}{
		"service_name": "svc",
		"environment":  "dev",
		"image":        "reg.io/app:v1",
		"owner":        "team",
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", jsonBody(t, payload))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, req)

	// No policies means no violations → allow.
	if w.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", w.Code, http.StatusOK)
	}
}

// ─── Integration: wire both handlers together ───

func TestIntegration_AllEndpoints(t *testing.T) {
	sets := []policy.PolicySet{
		{
			Name: "test-policy",
			Rules: []policy.Rule{
				{Type: policy.RuleTypeRequiredLabels, Severity: policy.SeverityDeny, Labels: []string{"app"}, Description: "app label"},
				{Type: policy.RuleTypeMaxCPU, Severity: policy.SeverityWarn, Value: 4, Description: "cpu limit"},
			},
		},
	}

	src := &stubPolicySource{ready: true, policies: sets}
	healthH := NewHealth(src, testLogger(t))
	evalH := NewEvaluate(src, testLogger(t))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthH.Healthz)
	mux.HandleFunc("GET /readyz", healthH.Readyz)
	mux.HandleFunc("POST /v1/evaluate", evalH.ServeHTTP)

	server := httptest.NewServer(mux)
	defer server.Close()

	// Test /healthz
	{
		resp, err := http.Get(server.URL + "/healthz")
		if err != nil {
			t.Fatalf("/healthz request failed: %v", err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Errorf("/healthz: failed to close body: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("/healthz: got %d, want %d", resp.StatusCode, http.StatusOK)
		}
	}

	// Test /readyz
	{
		resp, err := http.Get(server.URL + "/readyz")
		if err != nil {
			t.Fatalf("/readyz request failed: %v", err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Errorf("/readyz: failed to close body: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("/readyz: got %d, want %d", resp.StatusCode, http.StatusOK)
		}
	}

	// Test /v1/evaluate with valid request → allow
	{
		payload := map[string]interface{}{
			"service_name": "svc",
			"environment":  "dev",
			"image":        "reg.io/app:v1",
			"owner":        "team",
			"labels":       map[string]string{"app": "svc"},
		}

		resp, err := http.Post(server.URL+"/v1/evaluate", "application/json", jsonBody(t, payload))
		if err != nil {
			t.Fatalf("/v1/evaluate request failed: %v", err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Errorf("/v1/evaluate: failed to close body: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("/v1/evaluate (allow): got %d, want %d", resp.StatusCode, http.StatusOK)
		}
	}

	// Test /v1/evaluate with missing label → deny
	{
		payload := map[string]interface{}{
			"service_name": "svc",
			"environment":  "dev",
			"image":        "reg.io/app:v1",
			"owner":        "team",
		}

		resp, err := http.Post(server.URL+"/v1/evaluate", "application/json", jsonBody(t, payload))
		if err != nil {
			t.Fatalf("/v1/evaluate request failed: %v", err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Errorf("/v1/evaluate: failed to close body: %v", err)
		}
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("/v1/evaluate (deny): got %d, want %d", resp.StatusCode, http.StatusUnprocessableEntity)
		}
	}
}

// ─── Helpers ───

func jsonBody(t *testing.T, v any) io.Reader {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return bytes.NewReader(data)
}

func decodeBody(t *testing.T, body io.Reader, v any) {
	t.Helper()
	if err := json.NewDecoder(body).Decode(v); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
}

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
