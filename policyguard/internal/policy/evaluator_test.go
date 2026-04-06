package policy

import (
	"testing"
)

func TestEvaluate_Allow(t *testing.T) {
	sets := []PolicySet{
		{
			Name: "test",
			Rules: []Rule{
				{Type: RuleTypeRequiredLabels, Severity: SeverityDeny, Labels: []string{"app"}, Description: "must have app label"},
				{Type: RuleTypeMaxCPU, Severity: SeverityWarn, Value: 4, Description: "max 4 CPU"},
				{Type: RuleTypeMaxMemory, Severity: SeverityWarn, Value: 8192, Description: "max 8 GiB"},
				{Type: RuleTypeMinReplicas, Severity: SeverityDeny, Value: 2, Description: "min 2 replicas"},
				{Type: RuleTypeImageRegex, Severity: SeverityDeny, RegexPattern: "^[a-z][a-z0-9./-]+:[a-z0-9.]+$", Description: "image pattern"},
				{Type: RuleTypeForbiddenRegistry, Severity: SeverityDeny, Registries: []string{"localhost:"}, Description: "no localhost"},
				{Type: RuleTypeForbiddenCaps, Severity: SeverityDeny, Capabilities: []string{"SYS_ADMIN"}, Description: "no sys_admin"},
			},
		},
	}

	req := EvaluationRequest{
		ServiceName:  "my-service",
		Environment:  "production",
		Image:        "registry.example.com/my-app:v1.2.3",
		CPU:          2,
		Memory:       4096,
		Replicas:     3,
		Labels:       map[string]string{"app": "my-service"},
		Capabilities: []string{"NET_BIND_SERVICE"},
	}

	result := Evaluate(req, sets)

	if result.Decision != DecisionAllow {
		t.Errorf("got decision %s, want %s", result.Decision, DecisionAllow)
	}
	if len(result.Violations) != 0 {
		t.Errorf("got %d violations, want 0: %v", len(result.Violations), result.Violations)
	}
	if len(result.Warnings) != 0 {
		t.Errorf("got %d warnings, want 0", len(result.Warnings))
	}
}

func TestEvaluate_Deny_MissingLabels(t *testing.T) {
	sets := []PolicySet{
		{
			Name: "labels-policy",
			Rules: []Rule{
				{Type: RuleTypeRequiredLabels, Severity: SeverityDeny, Labels: []string{"app", "team"}, Description: "must have app and team labels"},
			},
		},
	}

	req := EvaluationRequest{
		ServiceName: "svc",
		Environment: "staging",
		Image:       "reg.io/app:v1",
		Labels:      map[string]string{"app": "svc"}, // missing "team"
	}

	result := Evaluate(req, sets)

	if result.Decision != DecisionDeny {
		t.Errorf("got decision %s, want %s", result.Decision, DecisionDeny)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("got %d violations, want 1", len(result.Violations))
	}
	if result.Violations[0].RuleType != RuleTypeRequiredLabels {
		t.Errorf("got rule type %s, want %s", result.Violations[0].RuleType, RuleTypeRequiredLabels)
	}
	if result.Violations[0].PolicyName != "labels-policy" {
		t.Errorf("got policy name %q, want %q", result.Violations[0].PolicyName, "labels-policy")
	}
}

func TestEvaluate_Deny_ForbiddenRegistry(t *testing.T) {
	sets := []PolicySet{
		{
			Name: "registry-policy",
			Rules: []Rule{
				{Type: RuleTypeForbiddenRegistry, Severity: SeverityDeny, Registries: []string{"localhost:", "docker.io/library/"}, Description: "no bad registries"},
			},
		},
	}

	tests := []struct {
		name  string
		image string
	}{
		{"localhost image", "localhost:5000/myimage:v1"},
		{"docker hub library", "docker.io/library/nginx:latest"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := EvaluationRequest{
				ServiceName: "svc",
				Environment: "dev",
				Image:       tc.image,
				Labels:      map[string]string{},
			}

			result := Evaluate(req, sets)

			if result.Decision != DecisionDeny {
				t.Errorf("got decision %s, want %s", result.Decision, DecisionDeny)
			}
			if len(result.Violations) == 0 {
				t.Error("expected violations for forbidden registry")
			}
		})
	}
}

func TestEvaluate_Warn_ExceedsCPU(t *testing.T) {
	sets := []PolicySet{
		{
			Name: "resource-policy",
			Rules: []Rule{
				{Type: RuleTypeMaxCPU, Severity: SeverityWarn, Value: 4, Description: "warn if > 4 CPU"},
			},
		},
	}

	req := EvaluationRequest{
		ServiceName: "svc",
		Environment: "dev",
		Image:       "reg.io/app:v1",
		CPU:         8,
		Labels:      map[string]string{},
	}

	result := Evaluate(req, sets)

	if result.Decision != DecisionWarn {
		t.Errorf("got decision %s, want %s", result.Decision, DecisionWarn)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("got %d warnings, want 1", len(result.Warnings))
	}
}

func TestEvaluate_Deny_ExceedsMemory(t *testing.T) {
	sets := []PolicySet{
		{
			Name: "resource-policy",
			Rules: []Rule{
				{Type: RuleTypeMaxMemory, Severity: SeverityDeny, Value: 8192, Description: "max 8 GiB"},
			},
		},
	}

	req := EvaluationRequest{
		ServiceName: "svc",
		Environment: "production",
		Image:       "reg.io/app:v1",
		Memory:      16384,
		Labels:      map[string]string{},
	}

	result := Evaluate(req, sets)

	if result.Decision != DecisionDeny {
		t.Errorf("got decision %s, want %s", result.Decision, DecisionDeny)
	}
}

func TestEvaluate_Deny_TooFewReplicas(t *testing.T) {
	sets := []PolicySet{
		{
			Name: "ha-policy",
			Rules: []Rule{
				{Type: RuleTypeMinReplicas, Severity: SeverityDeny, Value: 3, Description: "min 3 replicas"},
			},
		},
	}

	req := EvaluationRequest{
		ServiceName: "svc",
		Environment: "production",
		Image:       "reg.io/app:v1",
		Replicas:    1,
		Labels:      map[string]string{},
	}

	result := Evaluate(req, sets)

	if result.Decision != DecisionDeny {
		t.Errorf("got decision %s, want %s", result.Decision, DecisionDeny)
	}
}

func TestEvaluate_Deny_ForbiddenCapabilities(t *testing.T) {
	sets := []PolicySet{
		{
			Name: "security-policy",
			Rules: []Rule{
				{Type: RuleTypeForbiddenCaps, Severity: SeverityDeny, Capabilities: []string{"SYS_ADMIN", "NET_RAW"}, Description: "no privileged caps"},
			},
		},
	}

	req := EvaluationRequest{
		ServiceName:  "svc",
		Environment:  "production",
		Image:        "reg.io/app:v1",
		Capabilities: []string{"sys_admin"}, // case-insensitive
		Labels:       map[string]string{},
	}

	result := Evaluate(req, sets)

	if result.Decision != DecisionDeny {
		t.Errorf("got decision %s, want %s", result.Decision, DecisionDeny)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("got %d violations, want 1", len(result.Violations))
	}
}

func TestEvaluate_Deny_ImageRegexMismatch(t *testing.T) {
	sets := []PolicySet{
		{
			Name: "naming-policy",
			Rules: []Rule{
				{Type: RuleTypeImageRegex, Severity: SeverityDeny, RegexPattern: "^[a-z][a-z0-9./-]+:[a-z0-9.]+$", Description: "image naming"},
			},
		},
	}

	tests := []struct {
		name     string
		image    string
		wantDeny bool
	}{
		{"valid image", "registry.example.com/my-app:v1.2.3", false},
		{"uppercase not allowed", "registry.example.com/My-App:v1", true},
		{"no tag", "registry.example.com/my-app", true},
		{"empty image", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := EvaluationRequest{
				ServiceName: "svc",
				Environment: "dev",
				Image:       tc.image,
				Labels:      map[string]string{},
			}

			result := Evaluate(req, sets)

			if tc.wantDeny && result.Decision != DecisionDeny {
				t.Errorf("got decision %s, want %s", result.Decision, DecisionDeny)
			}
			if !tc.wantDeny && result.Decision == DecisionDeny {
				t.Errorf("got deny, expected allow for image %q", tc.image)
			}
		})
	}
}

func TestEvaluate_MultipleViolations(t *testing.T) {
	sets := []PolicySet{
		{
			Name: "multi-policy",
			Rules: []Rule{
				{Type: RuleTypeRequiredLabels, Severity: SeverityDeny, Labels: []string{"app", "team"}, Description: "labels"},
				{Type: RuleTypeMaxCPU, Severity: SeverityDeny, Value: 2, Description: "max CPU"},
				{Type: RuleTypeMaxMemory, Severity: SeverityWarn, Value: 4096, Description: "max memory"},
			},
		},
	}

	req := EvaluationRequest{
		ServiceName: "svc",
		Environment: "production",
		Image:       "reg.io/app:v1",
		CPU:         8,                   // exceeds max
		Memory:      8192,                // exceeds max (warn)
		Labels:      map[string]string{}, // missing labels
	}

	result := Evaluate(req, sets)

	if result.Decision != DecisionDeny {
		t.Errorf("got decision %s, want %s", result.Decision, DecisionDeny)
	}
	if len(result.Violations) != 2 {
		t.Errorf("got %d violations, want 2 (missing labels + CPU)", len(result.Violations))
	}
	if len(result.Warnings) != 1 {
		t.Errorf("got %d warnings, want 1 (memory)", len(result.Warnings))
	}

	// Verify explanation is non-empty
	if result.Explanation == "" {
		t.Error("explanation should not be empty for denied request")
	}
}

func TestEvaluate_MultiplePolicySets(t *testing.T) {
	sets := []PolicySet{
		{
			Name: "security",
			Rules: []Rule{
				{Type: RuleTypeRequiredLabels, Severity: SeverityDeny, Labels: []string{"app"}, Description: "security label"},
			},
		},
		{
			Name: "resources",
			Rules: []Rule{
				{Type: RuleTypeMaxCPU, Severity: SeverityWarn, Value: 4, Description: "CPU limit"},
			},
		},
	}

	req := EvaluationRequest{
		ServiceName: "svc",
		Environment: "staging",
		Image:       "reg.io/app:v1",
		CPU:         2,
		Labels:      map[string]string{"app": "svc"},
	}

	result := Evaluate(req, sets)

	if result.Decision != DecisionAllow {
		t.Errorf("got decision %s, want %s", result.Decision, DecisionAllow)
	}
}

func TestEvaluate_WarnNoDeny(t *testing.T) {
	sets := []PolicySet{
		{
			Name: "warn-only",
			Rules: []Rule{
				{Type: RuleTypeMaxCPU, Severity: SeverityWarn, Value: 4, Description: "cpu warn"},
				{Type: RuleTypeMaxMemory, Severity: SeverityWarn, Value: 8192, Description: "mem warn"},
			},
		},
	}

	req := EvaluationRequest{
		ServiceName: "svc",
		Environment: "dev",
		Image:       "reg.io/app:v1",
		CPU:         16,
		Memory:      32768,
		Labels:      map[string]string{},
	}

	result := Evaluate(req, sets)

	if result.Decision != DecisionWarn {
		t.Errorf("got decision %s, want %s", result.Decision, DecisionWarn)
	}
	if len(result.Warnings) != 2 {
		t.Errorf("got %d warnings, want 2", len(result.Warnings))
	}
	if len(result.Violations) != 0 {
		t.Errorf("got %d violations, want 0", len(result.Violations))
	}
}

func TestEvaluate_EvidenceRefs(t *testing.T) {
	sets := []PolicySet{
		{
			Name: "test-policy",
			Rules: []Rule{
				{Type: RuleTypeRequiredLabels, Severity: SeverityDeny, Labels: []string{"app"}, Description: "must have app"},
			},
		},
	}

	req := EvaluationRequest{
		ServiceName: "svc",
		Environment: "dev",
		Image:       "reg.io/app:v1",
		Labels:      map[string]string{}, // missing "app"
	}

	result := Evaluate(req, sets)

	if len(result.EvidenceRefs) != 1 {
		t.Fatalf("got %d evidence refs, want 1", len(result.EvidenceRefs))
	}
	if result.EvidenceRefs[0].PolicyName != "test-policy" {
		t.Errorf("got evidence policy %q, want %q", result.EvidenceRefs[0].PolicyName, "test-policy")
	}
	if result.EvidenceRefs[0].RuleType != RuleTypeRequiredLabels {
		t.Errorf("got evidence rule type %s, want %s", result.EvidenceRefs[0].RuleType, RuleTypeRequiredLabels)
	}
}

func TestEvaluate_EmptySlices(t *testing.T) {
	sets := []PolicySet{
		{
			Name:  "empty",
			Rules: []Rule{},
		},
	}

	req := EvaluationRequest{
		ServiceName: "svc",
		Environment: "dev",
		Image:       "reg.io/app:v1",
		Labels:      map[string]string{},
	}

	result := Evaluate(req, sets)

	// JSON consistency: slices should be non-nil empty
	if result.Violations == nil {
		t.Error("violations should be non-nil empty slice")
	}
	if result.Warnings == nil {
		t.Error("warnings should be non-nil empty slice")
	}
	if result.EvidenceRefs == nil {
		t.Error("evidence_refs should be non-nil empty slice")
	}
}

func TestAggregateDecision(t *testing.T) {
	tests := []struct {
		name       string
		violations []RuleViolation
		warnings   []RuleViolation
		want       Decision
	}{
		{
			name:       "empty everything",
			violations: nil,
			warnings:   nil,
			want:       DecisionAllow,
		},
		{
			name:     "warnings only",
			warnings: []RuleViolation{{Severity: SeverityWarn}},
			want:     DecisionWarn,
		},
		{
			name:       "deny violation only",
			violations: []RuleViolation{{Severity: SeverityDeny}},
			want:       DecisionDeny,
		},
		{
			name:       "deny trumps warnings",
			violations: []RuleViolation{{Severity: SeverityDeny}},
			warnings:   []RuleViolation{{Severity: SeverityWarn}},
			want:       DecisionDeny,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := AggregateDecision(tc.violations, tc.warnings)
			if got != tc.want {
				t.Errorf("got decision %s, want %s", got, tc.want)
			}
		})
	}
}

func TestBuildExplanation(t *testing.T) {
	tests := []struct {
		name     string
		decision Decision
		wantSub  string
	}{
		{
			name:     "allow",
			decision: DecisionAllow,
			wantSub:  "no policy violations",
		},
		{
			name:     "warn",
			decision: DecisionWarn,
			wantSub:  "warning",
		},
		{
			name:     "deny",
			decision: DecisionDeny,
			wantSub:  "violation",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			explanation := BuildExplanation(tc.decision, nil, nil)
			if explanation == "" {
				t.Fatal("explanation should not be empty")
			}
		})
	}
}

func FuzzEvaluate(f *testing.F) {
	f.Add("svc", "production", "reg.io/app:v1", 2.0, 4096.0, 3, "app")
	f.Add("", "", "", 0.0, 0.0, 0, "")
	f.Add("svc", "dev", "REGISTRY.IO/APP:V1", 100.0, 1000000.0, -1, "")

	f.Fuzz(func(t *testing.T, svc, env, image string, cpu, memory float64, replicas int, label string) {
		sets := []PolicySet{
			{
				Name: "fuzz-policy",
				Rules: []Rule{
					{Type: RuleTypeRequiredLabels, Severity: SeverityDeny, Labels: []string{label}, Description: "label check"},
					{Type: RuleTypeMaxCPU, Severity: SeverityWarn, Value: cpu, Description: "cpu check"},
					{Type: RuleTypeImageRegex, Severity: SeverityDeny, RegexPattern: "^[a-z]+$", Description: "regex check"},
				},
			},
		}

		req := EvaluationRequest{
			ServiceName: svc,
			Environment: env,
			Image:       image,
			CPU:         cpu,
			Memory:      memory,
			Replicas:    replicas,
			Labels:      map[string]string{label: "value"},
		}

		// Should never panic.
		_ = Evaluate(req, sets)
	})
}
