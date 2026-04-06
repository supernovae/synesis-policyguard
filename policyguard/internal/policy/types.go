// Package policy defines the domain types, evaluator, parser, and loader
// for the policy engine.
package policy

import (
	"fmt"
	"strings"
)

// ─── Severity constants ───

// Severity declares how a rule violation should be treated.
type Severity string

const (
	SeverityDeny Severity = "deny"
	SeverityWarn Severity = "warn"
)

func (s Severity) IsValid() bool {
	return s == SeverityDeny || s == SeverityWarn
}

// ─── Decision constants ───

// Decision is the final verdict after evaluating all rules.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionWarn  Decision = "warn"
	DecisionDeny  Decision = "deny"
)

// ─── Input types ───

// EvaluationRequest is the JSON body accepted at POST /v1/evaluate.
type EvaluationRequest struct {
	ServiceName  string            `json:"service_name"`
	Environment  string            `json:"environment"`
	Image        string            `json:"image"`
	CPU          float64           `json:"cpu"`    // CPU cores
	Memory       float64           `json:"memory"` // Memory in MiB
	Replicas     int               `json:"replicas"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	Owner        string            `json:"owner"`
	Capabilities []string          `json:"capabilities"`
}

// ─── Policy definition types (loaded from YAML) ───

// RuleType identifies the kind of policy check.
type RuleType string

const (
	RuleTypeRequiredLabels    RuleType = "required_labels"
	RuleTypeForbiddenRegistry RuleType = "forbidden_registry"
	RuleTypeMaxCPU            RuleType = "max_cpu"
	RuleTypeMaxMemory         RuleType = "max_memory"
	RuleTypeForbiddenCaps     RuleType = "forbidden_capabilities"
	RuleTypeMinReplicas       RuleType = "min_replicas"
	RuleTypeImageRegex        RuleType = "image_regex"
)

// YAMLPolicy represents the top-level structure in a policy YAML file.
type YAMLPolicy struct {
	Policies []YAMLPolicySet `yaml:"policies"`
}

// YAMLPolicySet is a single named policy block.
type YAMLPolicySet struct {
	Name         string         `yaml:"name"`
	Environments []string       `yaml:"environments"` // empty means all
	Overrides    []YAMLOverride `yaml:"overrides"`
	Rules        []YAMLRule     `yaml:"rules"`
}

// YAMLPolicyEnvironmentOverride provides rule overrides per environment.
type YAMLOverride struct {
	Environment string     `yaml:"environment"`
	Rules       []YAMLRule `yaml:"rules"`
}

// YAMLRule is a single rule definition as it appears in YAML.
type YAMLRule struct {
	Type         RuleType `yaml:"type"`
	Severity     Severity `yaml:"severity"`
	Labels       []string `yaml:"labels"`
	Registries   []string `yaml:"registries"`
	Value        float64  `yaml:"value"` // Used for max_cpu, max_memory, min_replicas
	Capabilities []string `yaml:"capabilities"`
	RegexPattern string   `yaml:"regex_pattern"`
	Description  string   `yaml:"description"`
}

// ─── Resolved runtime types ───

// PolicySet is a fully resolved policy set for a specific environment.
// It is the result of merging base rules with environment overrides.
type PolicySet struct {
	Name  string
	Rules []Rule
}

// Rule is the resolved, validated form of a YAMLRule.
type Rule struct {
	Type         RuleType
	Severity     Severity
	Labels       []string
	Registries   []string
	Value        float64
	Capabilities []string
	RegexPattern string
	Description  string
}

// ─── Evaluation result types ───

// RuleViolation records a single rule that was not satisfied.
type RuleViolation struct {
	RuleType    RuleType `json:"rule_type"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Detail      string   `json:"detail"`
	PolicyName  string   `json:"policy_name"`
}

// EvaluationResult is the response returned to the caller of /v1/evaluate.
type EvaluationResult struct {
	Decision     Decision        `json:"decision"`
	Violations   []RuleViolation `json:"violations"`
	Warnings     []RuleViolation `json:"warnings"`
	Explanation  string          `json:"explanation"`
	EvidenceRefs []EvidenceRef   `json:"evidence_refs"`
}

// EvidenceRef is a machine-readable pointer to the violated rule configuration.
type EvidenceRef struct {
	PolicyName string   `json:"policy_name"`
	RuleType   RuleType `json:"rule_type"`
	Message    string   `json:"message"`
}

// ─── Helpers ───

// AggregateDecision returns the highest-severity decision across all violations.
func AggregateDecision(violations []RuleViolation, warnings []RuleViolation) Decision {
	for _, v := range violations {
		if v.Severity == SeverityDeny {
			return DecisionDeny
		}
	}
	if len(warnings) > 0 {
		return DecisionWarn
	}
	return DecisionAllow
}

// BuildExplanation creates a human-readable summary.
func BuildExplanation(decision Decision, violations []RuleViolation, warnings []RuleViolation) string {
	var sb strings.Builder

	switch decision {
	case DecisionAllow:
		sb.WriteString("Deployment request allowed — no policy violations detected.")
	case DecisionWarn:
		fmt.Fprintf(&sb, "Deployment request has %d warning(s).\n", len(warnings))
		for i, w := range warnings {
			fmt.Fprintf(&sb, "%d. [%s] %s: %s\n", i+1, w.Severity, w.RuleType, w.Description)
		}
	case DecisionDeny:
		fmt.Fprintf(&sb, "Deployment request denied — %d critical violation(s) found.\n", len(violations))
		for i, v := range violations {
			fmt.Fprintf(&sb, "%d. %s: %s\n", i+1, v.RuleType, v.Description)
		}
	}

	return strings.TrimSpace(sb.String())
}

// BuildEvidenceRefs creates machine-readable references from violations.
func BuildEvidenceRefs(violations []RuleViolation) []EvidenceRef {
	refs := make([]EvidenceRef, 0, len(violations))
	for _, v := range violations {
		refs = append(refs, EvidenceRef{
			PolicyName: v.PolicyName,
			RuleType:   v.RuleType,
			Message:    fmt.Sprintf("%s: %s", v.RuleType, v.Description),
		})
	}
	return refs
}
