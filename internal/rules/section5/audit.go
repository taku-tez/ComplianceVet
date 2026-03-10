package section5

import (
	"strings"

	"github.com/ComplianceVet/compliancevet/internal/parser"
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

// ---- CV5012: Audit log must be enabled ----

type cv5012Rule struct{}

func (r cv5012Rule) ID() string               { return "CV5012" }
func (r cv5012Rule) CISRef() string           { return standard + " §9.1" }
func (r cv5012Rule) Section() rules.CISSection { return rules.SectionNSACISA }
func (r cv5012Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv5012Rule) Description() string {
	return "Kubernetes audit logging must be enabled"
}
func (r cv5012Rule) Remediation() string {
	return "Configure --audit-log-path and --audit-policy-file on the API server"
}
func (r cv5012Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	var apiservers []parser.K8sObject
	for _, obj := range ctx.Objects {
		if obj.Kind == "Pod" && strings.Contains(strings.ToLower(obj.Name), "apiserver") {
			apiservers = append(apiservers, obj)
		}
	}
	if len(apiservers) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}

	var results []rules.CheckResult
	for _, obj := range apiservers {
		flags := getAPIServerFlagsFromPod(obj)
		hasPath := flags["--audit-log-path"] != ""
		hasPolicy := flags["--audit-policy-file"] != ""

		if hasPath && hasPolicy {
			results = append(results, passResult(r, obj))
		} else if hasPath {
			results = append(results, warnResult(r, obj, "--audit-log-path set but --audit-policy-file is missing"))
		} else {
			results = append(results, failResult(r, obj, "Audit logging is not configured"))
		}
	}
	return results
}

// ---- CV5013: Audit policy must log privileged operations ----

type cv5013Rule struct{}

func (r cv5013Rule) ID() string               { return "CV5013" }
func (r cv5013Rule) CISRef() string           { return standard + " §9.1" }
func (r cv5013Rule) Section() rules.CISSection { return rules.SectionNSACISA }
func (r cv5013Rule) Severity() rules.Severity  { return rules.SeverityMedium }
func (r cv5013Rule) Description() string {
	return "Audit policy must be configured (--audit-policy-file set)"
}
func (r cv5013Rule) Remediation() string {
	return "Create an audit policy file and pass it with --audit-policy-file to the API server"
}
func (r cv5013Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	// Look for AuditPolicy objects (if scanned from a file)
	var auditPolicies []parser.K8sObject
	for _, obj := range ctx.Objects {
		if obj.Kind == "Policy" && obj.APIVersion == "audit.k8s.io/v1" {
			auditPolicies = append(auditPolicies, obj)
		}
	}

	// Also check if any API server references --audit-policy-file
	var apiservers []parser.K8sObject
	for _, obj := range ctx.Objects {
		if obj.Kind == "Pod" && strings.Contains(strings.ToLower(obj.Name), "apiserver") {
			apiservers = append(apiservers, obj)
		}
	}

	if len(auditPolicies) == 0 && len(apiservers) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}

	var results []rules.CheckResult

	// Validate AuditPolicy objects
	for _, obj := range auditPolicies {
		rules_list, _ := obj.Spec["rules"].([]interface{})
		if len(rules_list) == 0 {
			results = append(results, warnResult(r, obj, "Audit policy has no rules defined"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}

	// Check API servers for audit policy flag
	for _, obj := range apiservers {
		flags := getAPIServerFlagsFromPod(obj)
		if flags["--audit-policy-file"] != "" {
			if len(auditPolicies) == 0 {
				// Policy file referenced but not scanned
				results = append(results, passResult(r, obj))
			}
		} else if len(auditPolicies) == 0 {
			results = append(results, failResult(r, obj, "--audit-policy-file is not configured"))
		}
	}

	if len(results) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	return results
}

func getAPIServerFlagsFromPod(obj parser.K8sObject) map[string]string {
	flags := map[string]string{}
	containers, _ := obj.Spec["containers"].([]interface{})
	for _, c := range containers {
		cm, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		for _, field := range []string{"command", "args"} {
			if raw, ok := cm[field]; ok {
				switch v := raw.(type) {
				case []interface{}:
					for _, item := range v {
						s, _ := item.(string)
						parseFlagInto(s, flags)
					}
				case string:
					parseFlagInto(v, flags)
				}
			}
		}
	}
	return flags
}

func parseFlagInto(s string, out map[string]string) {
	if !strings.HasPrefix(s, "-") {
		return
	}
	s = strings.TrimLeft(s, "-")
	if idx := strings.Index(s, "="); idx >= 0 {
		out["--"+s[:idx]] = s[idx+1:]
	} else {
		out["--"+s] = ""
	}
}
