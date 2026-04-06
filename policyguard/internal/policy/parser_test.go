package policy

import (
	"testing"
)

func TestParseBytes(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantSets    int
		wantErr     bool
		errContains string
	}{
		{
			name: "valid single policy set",
			input: `
policies:
  - name: test-policy
    environments: []
    rules:
      - type: required_labels
        severity: deny
        labels: ["app"]
        description: "Must have app label"
`,
			wantSets: 1,
			wantErr:  false,
		},
		{
			name: "missing policy name",
			input: `
policies:
  - name: ""
    rules: []
`,
			wantErr:     true,
			errContains: "name is required",
		},
		{
			name: "invalid severity",
			input: `
policies:
  - name: bad
    rules:
      - type: required_labels
        severity: critical
        labels: ["app"]
        description: "test"
`,
			wantErr:     true,
			errContains: "invalid severity",
		},
		{
			name: "unknown rule type",
			input: `
policies:
  - name: test
    rules:
      - type: unknown_type
        severity: deny
        description: "bad type"
`,
			wantErr:     true,
			errContains: "unknown rule type",
		},
		{
			name: "empty description",
			input: `
policies:
  - name: test
    rules:
      - type: required_labels
        severity: deny
        labels: ["app"]
        description: ""
`,
			wantErr:     true,
			errContains: "description is required",
		},
		{
			name: "required_labels without labels",
			input: `
policies:
  - name: test
    rules:
      - type: required_labels
        severity: deny
        labels: []
        description: "missing labels"
`,
			wantErr:     true,
			errContains: "must specify at least one label",
		},
		{
			name: "forbidden_registry without registries",
			input: `
policies:
  - name: test
    rules:
      - type: forbidden_registry
        severity: deny
        description: "no registries"
`,
			wantErr:     true,
			errContains: "must specify at least one registry",
		},
		{
			name: "max_cpu with non-positive value",
			input: `
policies:
  - name: test
    rules:
      - type: max_cpu
        severity: deny
        value: 0
        description: "zero cpu"
`,
			wantErr:     true,
			errContains: "positive value",
		},
		{
			name: "forbidden_capabilities without capabilities",
			input: `
policies:
  - name: test
    rules:
      - type: forbidden_capabilities
        severity: deny
        description: "no caps"
`,
			wantErr:     true,
			errContains: "must specify at least one capability",
		},
		{
			name: "image_regex with missing pattern",
			input: `
policies:
  - name: test
    rules:
      - type: image_regex
        severity: deny
        description: "no pattern"
`,
			wantErr:     true,
			errContains: "must specify a regex_pattern",
		},
		{
			name: "image_regex with bad regex",
			input: `
policies:
  - name: test
    rules:
      - type: image_regex
        severity: deny
        regex_pattern: "[invalid"
        description: "bad regex"
`,
			wantErr:     true,
			errContains: "invalid regex",
		},
		{
			name: "min_replicas with zero value",
			input: `
policies:
  - name: test
    rules:
      - type: min_replicas
        severity: deny
        value: 0
        description: "zero replicas"
`,
			wantErr:     true,
			errContains: "positive value",
		},
		{
			name:        "empty file",
			input:       "",
			wantErr:     true,
			errContains: "no valid policy sets",
		},
		{
			name:        "invalid yaml syntax",
			input:       "policies:\n  - name: [\n    bad: ]",
			wantErr:     true,
			errContains: "unmarshal",
		},
		{
			name: "override without environment",
			input: `
policies:
  - name: test
    rules: []
    overrides:
      - environment: ""
        rules: []
`,
			wantErr:     true,
			errContains: "environment is required",
		},
		{
			name: "valid policy with override",
			input: `
policies:
  - name: production
    environments: ["production"]
    rules:
      - type: min_replicas
        severity: deny
        value: 3
        description: "Min 3 replicas in production"
    overrides:
      - environment: staging
        rules:
          - type: min_replicas
            severity: warn
            value: 1
            description: "At least 1 replica in staging"
`,
			wantSets: 1,
			wantErr:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sets, err := ParseBytes([]byte(tc.input))

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errContains != "" {
					if !containsStr(err.Error(), tc.errContains) {
						t.Errorf("error %q does not contain %q", err.Error(), tc.errContains)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := len(sets); got != tc.wantSets {
				t.Errorf("got %d policy sets, want %d", got, tc.wantSets)
			}
		})
	}
}

func TestParseBytes_MultiplePolicySets(t *testing.T) {
	input := `
policies:
  - name: security
    rules:
      - type: required_labels
        severity: deny
        labels: ["app"]
        description: "Must have app label"
  - name: resources
    rules:
      - type: max_cpu
        severity: warn
        value: 4
        description: "Max 4 CPU"
  - name: production
    environments: ["production"]
    rules:
      - type: min_replicas
        severity: deny
        value: 2
        description: "Min 2 replicas"
`
	sets, err := ParseBytes([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sets) != 3 {
		t.Errorf("got %d sets, want 3", len(sets))
	}
	expectedNames := []string{"security", "resources", "production"}
	for i, name := range expectedNames {
		if sets[i].Name != name {
			t.Errorf("set %d: got name %q, want %q", i, sets[i].Name, name)
		}
	}
}

func TestParseFile_NotFound(t *testing.T) {
	_, err := ParseFile("nonexistent/file.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestRuleType_IsValid(t *testing.T) {
	validTypes := []RuleType{
		RuleTypeRequiredLabels,
		RuleTypeForbiddenRegistry,
		RuleTypeMaxCPU,
		RuleTypeMaxMemory,
		RuleTypeForbiddenCaps,
		RuleTypeMinReplicas,
		RuleTypeImageRegex,
	}
	for _, rt := range validTypes {
		if !rt.IsValid() {
			t.Errorf("RuleType %q should be valid", rt)
		}
	}

	if RuleType("bogus").IsValid() {
		t.Error("bogus RuleType should not be valid")
	}
}

func TestSeverity_IsValid(t *testing.T) {
	if !SeverityDeny.IsValid() {
		t.Error("SeverityDeny should be valid")
	}
	if !SeverityWarn.IsValid() {
		t.Error("SeverityWarn should be valid")
	}
	if Severity("critical").IsValid() {
		t.Error("critical should not be valid")
	}
}

func FuzzParseBytes(f *testing.F) {
	// Seed corpus with valid YAML
	f.Add(`policies:
  - name: test
    rules:
      - type: required_labels
        severity: deny
        labels: ["app"]
        description: "Must have app label"
`)
	f.Add(``)
	f.Add(`not yaml at all: {{{`)
	f.Add(`policies: []`)

	f.Fuzz(func(t *testing.T, data string) {
		// Fuzz should never panic.
		_, _ = ParseBytes([]byte(data))
	})
}

func containsStr(haystack, needle string) bool {
	return len(haystack) >= len(needle) && haystack != "" && needle != "" && haystackIndex(haystack, needle) >= 0
}

func haystackIndex(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
