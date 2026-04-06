package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// ParseFile reads a YAML policy file and returns a slice of resolved PolicySets.
// Policies are resolved only once (no environment-specific filtering at parse time);
// environment resolution happens in the loader.
func ParseFile(path string) ([]PolicySet, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read policy file %s: %w", path, err)
	}
	return ParseBytes(data)
}

// ParseBytes unmarshals YAML bytes into validated PolicySets.
func ParseBytes(data []byte) ([]PolicySet, error) {
	var raw YAMLPolicy
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal policy yaml: %w", err)
	}

	sets := make([]PolicySet, 0, len(raw.Policies))
	for _, ps := range raw.Policies {
		set, err := resolvePolicySet(ps)
		if err != nil {
			return nil, fmt.Errorf("resolve policy set %q: %w", ps.Name, err)
		}
		sets = append(sets, set)
	}

	if len(sets) == 0 {
		return nil, fmt.Errorf("policy file contains no valid policy sets")
	}

	return sets, nil
}

// resolvePolicySet converts a YAMLPolicySet into a validated PolicySet.
func resolvePolicySet(raw YAMLPolicySet) (PolicySet, error) {
	if raw.Name == "" {
		return PolicySet{}, fmt.Errorf("policy set name is required")
	}

	rules := make([]Rule, 0, len(raw.Rules))
	for i, r := range raw.Rules {
		resolved, err := resolveRule(r)
		if err != nil {
			return PolicySet{}, fmt.Errorf("rule %d: %w", i, err)
		}
		rules = append(rules, resolved)
	}

	// Merge override rules — these are environment-specific additions.
	// We keep them as base rules tagged with "env:" prefix for now;
	// the loader will do environment-based filtering.
	for oi, ov := range raw.Overrides {
		if ov.Environment == "" {
			return PolicySet{}, fmt.Errorf("override %d: environment is required", oi)
		}
		for ri, r := range ov.Rules {
			resolved, err := resolveRule(r)
			if err != nil {
				return PolicySet{}, fmt.Errorf("override %d rule %d: %w", oi, ri, err)
			}
			rules = append(rules, resolved)
		}
	}

	return PolicySet{
		Name:  raw.Name,
		Rules: rules,
	}, nil
}

// validateRule checks a single rule for semantic validity.
func resolveRule(raw YAMLRule) (Rule, error) {
	if !raw.Type.IsValid() {
		return Rule{}, fmt.Errorf("unknown rule type %q", raw.Type)
	}
	if !raw.Severity.IsValid() {
		return Rule{}, fmt.Errorf("invalid severity %q (must be 'deny' or 'warn')", raw.Severity)
	}
	if raw.Description == "" {
		return Rule{}, fmt.Errorf("description is required for rule type %q", raw.Type)
	}

	// Type-specific validation.
	switch raw.Type {
	case RuleTypeRequiredLabels:
		if len(raw.Labels) == 0 {
			return Rule{}, fmt.Errorf("required_labels rule must specify at least one label")
		}
	case RuleTypeForbiddenRegistry:
		if len(raw.Registries) == 0 {
			return Rule{}, fmt.Errorf("forbidden_registry rule must specify at least one registry")
		}
	case RuleTypeMaxCPU, RuleTypeMaxMemory, RuleTypeMinReplicas:
		if raw.Value <= 0 {
			return Rule{}, fmt.Errorf("%s rule must have a positive value, got %f", raw.Type, raw.Value)
		}
	case RuleTypeForbiddenCaps:
		if len(raw.Capabilities) == 0 {
			return Rule{}, fmt.Errorf("forbidden_capabilities rule must specify at least one capability")
		}
	case RuleTypeImageRegex:
		if raw.RegexPattern == "" {
			return Rule{}, fmt.Errorf("image_regex rule must specify a regex_pattern")
		}
		if _, err := regexp.Compile(raw.RegexPattern); err != nil {
			return Rule{}, fmt.Errorf("image_regex rule has invalid regex: %w", err)
		}
	}

	return Rule(raw), nil
}

// IsValid checks if a RuleType is known.
func (r RuleType) IsValid() bool {
	switch r {
	case RuleTypeRequiredLabels, RuleTypeForbiddenRegistry,
		RuleTypeMaxCPU, RuleTypeMaxMemory, RuleTypeForbiddenCaps,
		RuleTypeMinReplicas, RuleTypeImageRegex:
		return true
	}
	return false
}
