package section4

import (
	"fmt"
	"strings"

	"github.com/ComplianceVet/compliancevet/internal/parser"
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

func resourceRef(obj parser.K8sObject) string {
	if obj.Namespace != "" {
		return fmt.Sprintf("%s/%s/%s", obj.Kind, obj.Namespace, obj.Name)
	}
	return fmt.Sprintf("%s/%s", obj.Kind, obj.Name)
}

func notApplicable(r rules.Rule) rules.CheckResult {
	return rules.CheckResult{
		RuleID:      r.ID(),
		CISRef:      r.CISRef(),
		Section:     r.Section(),
		Status:      rules.StatusNotApplicable,
		Severity:    r.Severity(),
		Description: r.Description(),
		Message:     "No applicable resources found in scanned manifests",
	}
}

func passResult(r rules.Rule, obj parser.K8sObject) rules.CheckResult {
	return rules.CheckResult{
		RuleID:      r.ID(),
		CISRef:      r.CISRef(),
		Section:     r.Section(),
		Status:      rules.StatusPass,
		Severity:    r.Severity(),
		Description: r.Description(),
		Resource:    resourceRef(obj),
		FilePath:    obj.SourceFile,
	}
}

func failResult(r rules.Rule, obj parser.K8sObject, message string) rules.CheckResult {
	return rules.CheckResult{
		RuleID:      r.ID(),
		CISRef:      r.CISRef(),
		Section:     r.Section(),
		Status:      rules.StatusFail,
		Severity:    r.Severity(),
		Description: r.Description(),
		Message:     message,
		Resource:    resourceRef(obj),
		FilePath:    obj.SourceFile,
		Remediation: r.Remediation(),
	}
}

func warnResult(r rules.Rule, obj parser.K8sObject, message string) rules.CheckResult {
	return rules.CheckResult{
		RuleID:      r.ID(),
		CISRef:      r.CISRef(),
		Section:     r.Section(),
		Status:      rules.StatusWarn,
		Severity:    r.Severity(),
		Description: r.Description(),
		Message:     message,
		Resource:    resourceRef(obj),
		FilePath:    obj.SourceFile,
		Remediation: r.Remediation(),
	}
}

// getRules returns policy rules from a ClusterRole or Role.
func getPolicyRules(obj parser.K8sObject) []map[string]interface{} {
	var result []map[string]interface{}
	rulesRaw, ok := obj.Raw["rules"]
	if !ok {
		return nil
	}
	rulesList, ok := rulesRaw.([]interface{})
	if !ok {
		return nil
	}
	for _, item := range rulesList {
		if m, ok := item.(map[string]interface{}); ok {
			result = append(result, m)
		}
	}
	return result
}

func sliceContains(slice []interface{}, val string) bool {
	for _, v := range slice {
		if s, ok := v.(string); ok && s == val {
			return true
		}
	}
	return false
}

func toStringSlice(v interface{}) []interface{} {
	s, ok := v.([]interface{})
	if !ok {
		return nil
	}
	return s
}

// ---- CV4001: No ClusterRole/Role with wildcard verbs ----

type cv4001Rule struct{}

func (r cv4001Rule) ID() string               { return "CV4001" }
func (r cv4001Rule) CISRef() string           { return "CIS 5.1.3" }
func (r cv4001Rule) Section() rules.CISSection { return rules.SectionPolicies }
func (r cv4001Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv4001Rule) Description() string {
	return "ClusterRole/Role must not use wildcard verb '*'"
}
func (r cv4001Rule) Remediation() string {
	return "Replace wildcard verbs with explicit verbs (get, list, watch, create, update, delete)"
}
func (r cv4001Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	var found []parser.K8sObject
	for _, obj := range ctx.Objects {
		if obj.Kind == "ClusterRole" || obj.Kind == "Role" {
			found = append(found, obj)
		}
	}
	if len(found) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range found {
		violated := false
		for _, rule := range getPolicyRules(obj) {
			verbs := toStringSlice(rule["verbs"])
			if sliceContains(verbs, "*") {
				violated = true
				break
			}
		}
		if violated {
			results = append(results, failResult(r, obj, "Role has wildcard verb '*' in rules"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

// ---- CV4002: No ClusterRole/Role with wildcard resources ----

type cv4002Rule struct{}

func (r cv4002Rule) ID() string               { return "CV4002" }
func (r cv4002Rule) CISRef() string           { return "CIS 5.1.3" }
func (r cv4002Rule) Section() rules.CISSection { return rules.SectionPolicies }
func (r cv4002Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv4002Rule) Description() string {
	return "ClusterRole/Role must not use wildcard resource '*'"
}
func (r cv4002Rule) Remediation() string {
	return "Replace wildcard resources with explicit resource names"
}
func (r cv4002Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	var found []parser.K8sObject
	for _, obj := range ctx.Objects {
		if obj.Kind == "ClusterRole" || obj.Kind == "Role" {
			found = append(found, obj)
		}
	}
	if len(found) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range found {
		violated := false
		for _, rule := range getPolicyRules(obj) {
			resources := toStringSlice(rule["resources"])
			if sliceContains(resources, "*") {
				violated = true
				break
			}
		}
		if violated {
			results = append(results, failResult(r, obj, "Role has wildcard resource '*' in rules"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

// ---- CV4003: default ServiceAccount not bound to ClusterRole ----

type cv4003Rule struct{}

func (r cv4003Rule) ID() string               { return "CV4003" }
func (r cv4003Rule) CISRef() string           { return "CIS 5.1.1" }
func (r cv4003Rule) Section() rules.CISSection { return rules.SectionPolicies }
func (r cv4003Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv4003Rule) Description() string {
	return "Default ServiceAccount must not be bound to a ClusterRole or Role"
}
func (r cv4003Rule) Remediation() string {
	return "Remove ClusterRoleBinding/RoleBinding that grants permissions to the 'default' ServiceAccount"
}
func (r cv4003Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	var bindings []parser.K8sObject
	for _, obj := range ctx.Objects {
		if obj.Kind == "ClusterRoleBinding" || obj.Kind == "RoleBinding" {
			bindings = append(bindings, obj)
		}
	}
	if len(bindings) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range bindings {
		subjectsRaw, _ := obj.Raw["subjects"]
		subjects, _ := subjectsRaw.([]interface{})
		violated := false
		for _, s := range subjects {
			sub, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			kind, _ := sub["kind"].(string)
			name, _ := sub["name"].(string)
			if kind == "ServiceAccount" && name == "default" {
				violated = true
				break
			}
		}
		if violated {
			results = append(results, failResult(r, obj, "Binding grants permissions to the 'default' ServiceAccount"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

// ---- CV4004: ServiceAccount automountServiceAccountToken=false ----

type cv4004Rule struct{}

func (r cv4004Rule) ID() string               { return "CV4004" }
func (r cv4004Rule) CISRef() string           { return "CIS 5.1.5" }
func (r cv4004Rule) Section() rules.CISSection { return rules.SectionPolicies }
func (r cv4004Rule) Severity() rules.Severity  { return rules.SeverityMedium }
func (r cv4004Rule) Description() string {
	return "ServiceAccount token auto-mounting should be disabled where not needed"
}
func (r cv4004Rule) Remediation() string {
	return "Set automountServiceAccountToken: false on ServiceAccount or Pod spec"
}
func (r cv4004Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	var found []parser.K8sObject
	for _, obj := range ctx.Objects {
		if obj.Kind == "ServiceAccount" {
			found = append(found, obj)
		}
	}
	if len(found) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range found {
		// Skip system service accounts
		if obj.Namespace == "kube-system" {
			continue
		}
		v, ok := obj.Raw["automountServiceAccountToken"]
		if ok {
			b, isBool := v.(bool)
			if isBool && !b {
				results = append(results, passResult(r, obj))
				continue
			}
		}
		results = append(results, warnResult(r, obj, "automountServiceAccountToken is not explicitly set to false"))
	}
	if len(results) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	return results
}

// suppress unused import
var _ = strings.Contains
