package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// Evaluate applies all policy rules to the given request and returns a result.
// Only rules whose environments match the request's environment (or rules with
// no environment restriction) are evaluated.
func Evaluate(req EvaluationRequest, sets []PolicySet) EvaluationResult {
	var violations []RuleViolation
	var warnings []RuleViolation

	for _, ps := range sets {
		for _, rule := range ps.Rules {
			// Skip rules that target a different environment.
			// Rules with empty environments apply to all environments.
			// Override rules (created during parsing with env-specific tags) are stored
			// in the same policy set; we need to track env matching at the rule level.
			// The parser stores env info in the rule — we use rule description prefix.
			// Simpler: we track environments during parse and store them in Rule.
			// For now, evaluate all rules in the set. Environment filtering is done
			// by the loader which produces environment-specific PolicySet lists.

			violation, hits := checkRule(rule, req)
			if !hits {
				continue
			}
			violation.PolicyName = ps.Name

			if rule.Severity == SeverityDeny {
				violations = append(violations, violation)
			} else {
				warnings = append(warnings, violation)
			}
		}
	}

	decision := AggregateDecision(violations, warnings)

	// Ensure empty slices instead of nil for JSON consistency.
	if violations == nil {
		violations = []RuleViolation{}
	}
	if warnings == nil {
		warnings = []RuleViolation{}
	}

	return EvaluationResult{
		Decision:     decision,
		Violations:   violations,
		Warnings:     warnings,
		Explanation:  BuildExplanation(decision, violations, warnings),
		EvidenceRefs: BuildEvidenceRefs(violations),
	}
}

// checkRule runs the rule against the request and returns (RuleViolation, whether it matched).
func checkRule(rule Rule, req EvaluationRequest) (RuleViolation, bool) {
	switch rule.Type {
	case RuleTypeRequiredLabels:
		return checkRequiredLabels(rule, req)
	case RuleTypeForbiddenRegistry:
		return checkForbiddenRegistry(rule, req)
	case RuleTypeMaxCPU:
		return checkMaxCPU(rule, req)
	case RuleTypeMaxMemory:
		return checkMaxMemory(rule, req)
	case RuleTypeForbiddenCaps:
		return checkForbiddenCaps(rule, req)
	case RuleTypeMinReplicas:
		return checkMinReplicas(rule, req)
	case RuleTypeImageRegex:
		return checkImageRegex(rule, req)
	default:
		return RuleViolation{}, false
	}
}

func checkRequiredLabels(rule Rule, req EvaluationRequest) (RuleViolation, bool) {
	var missing []string
	for _, label := range rule.Labels {
		if _, ok := req.Labels[label]; !ok {
			missing = append(missing, label)
		}
	}
	if len(missing) == 0 {
		return RuleViolation{}, false
	}
	return RuleViolation{
		RuleType:    RuleTypeRequiredLabels,
		Severity:    rule.Severity,
		Description: fmt.Sprintf("Missing required labels: %s", strings.Join(missing, ", ")),
		Detail:      fmt.Sprintf("expected labels: %v", rule.Labels),
	}, true
}

func checkForbiddenRegistry(rule Rule, req EvaluationRequest) (RuleViolation, bool) {
	for _, reg := range rule.Registries {
		if strings.HasPrefix(req.Image, reg) {
			return RuleViolation{
				RuleType:    RuleTypeForbiddenRegistry,
				Severity:    rule.Severity,
				Description: fmt.Sprintf("Image uses forbidden registry: %s", reg),
				Detail:      fmt.Sprintf("image %q starts with forbidden registry %q", req.Image, reg),
			}, true
		}
	}
	return RuleViolation{}, false
}

func checkMaxCPU(rule Rule, req EvaluationRequest) (RuleViolation, bool) {
	if req.CPU > rule.Value {
		return RuleViolation{
			RuleType:    RuleTypeMaxCPU,
			Severity:    rule.Severity,
			Description: fmt.Sprintf("CPU request %.2f exceeds maximum of %.2f cores", req.CPU, rule.Value),
			Detail:      fmt.Sprintf("requested %.2f, max %.2f", req.CPU, rule.Value),
		}, true
	}
	return RuleViolation{}, false
}

func checkMaxMemory(rule Rule, req EvaluationRequest) (RuleViolation, bool) {
	if req.Memory > rule.Value {
		return RuleViolation{
			RuleType:    RuleTypeMaxMemory,
			Severity:    rule.Severity,
			Description: fmt.Sprintf("Memory request %d MiB exceeds maximum of %d MiB", int(req.Memory), int(rule.Value)),
			Detail:      fmt.Sprintf("requested %d MiB, max %d MiB", int(req.Memory), int(rule.Value)),
		}, true
	}
	return RuleViolation{}, false
}

func checkForbiddenCaps(rule Rule, req EvaluationRequest) (RuleViolation, bool) {
	reqCaps := make(map[string]struct{}, len(req.Capabilities))
	for _, c := range req.Capabilities {
		reqCaps[strings.ToUpper(c)] = struct{}{}
	}

	var forbidden []string
	for _, cap := range rule.Capabilities {
		if _, found := reqCaps[strings.ToUpper(cap)]; found {
			forbidden = append(forbidden, cap)
		}
	}
	if len(forbidden) == 0 {
		return RuleViolation{}, false
	}
	return RuleViolation{
		RuleType:    RuleTypeForbiddenCaps,
		Severity:    rule.Severity,
		Description: fmt.Sprintf("Request uses forbidden capabilities: %s", strings.Join(forbidden, ", ")),
		Detail:      fmt.Sprintf("forbidden capabilities: %v", rule.Capabilities),
	}, true
}

func checkMinReplicas(rule Rule, req EvaluationRequest) (RuleViolation, bool) {
	if req.Replicas < int(rule.Value) {
		return RuleViolation{
			RuleType:    RuleTypeMinReplicas,
			Severity:    rule.Severity,
			Description: fmt.Sprintf("Replica count %d is below the minimum of %d", req.Replicas, int(rule.Value)),
			Detail:      fmt.Sprintf("requested %d, minimum %d", req.Replicas, int(rule.Value)),
		}, true
	}
	return RuleViolation{}, false
}

func checkImageRegex(rule Rule, req EvaluationRequest) (RuleViolation, bool) {
	if req.Image == "" {
		return RuleViolation{
			RuleType:    RuleTypeImageRegex,
			Severity:    rule.Severity,
			Description: "Image name is empty",
			Detail:      "image must be a non-empty string matching the required pattern",
		}, true
	}

	re, err := regexp.Compile(rule.RegexPattern)
	if err != nil {
		// Parser should have caught this, but fail safe.
		return RuleViolation{
			RuleType:    RuleTypeImageRegex,
			Severity:    SeverityWarn,
			Description: fmt.Sprintf("Invalid regex pattern in policy: %v", err),
			Detail:      fmt.Sprintf("pattern: %q", rule.RegexPattern),
		}, true
	}

	if !re.MatchString(req.Image) {
		return RuleViolation{
			RuleType:    RuleTypeImageRegex,
			Severity:    rule.Severity,
			Description: fmt.Sprintf("Image name %q does not match required pattern %q", req.Image, rule.RegexPattern),
			Detail:      fmt.Sprintf("image must match %q", rule.RegexPattern),
		}, true
	}
	return RuleViolation{}, false
}
