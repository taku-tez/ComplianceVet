package section4

import (
	"strings"

	"github.com/ComplianceVet/compliancevet/internal/parser"
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

// ---- CV4011: Secrets must not be exposed as environment variables ----

type cv4011Rule struct{}

func (r cv4011Rule) ID() string               { return "CV4011" }
func (r cv4011Rule) CISRef() string           { return "CIS 5.4.1" }
func (r cv4011Rule) Section() rules.CISSection { return rules.SectionPolicies }
func (r cv4011Rule) Severity() rules.Severity  { return rules.SeverityMedium }
func (r cv4011Rule) Description() string {
	return "Secrets must not be exposed as plain environment variables"
}
func (r cv4011Rule) Remediation() string {
	return "Use secretKeyRef in env vars or mount secrets as volumes instead of hardcoding them"
}
func (r cv4011Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := getWorkloadObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		podSpec := getPodTemplateSpec(obj)
		violated := false
		for _, c := range getAllContainers(podSpec) {
			envVars, _ := c["env"].([]interface{})
			for _, e := range envVars {
				env, ok := e.(map[string]interface{})
				if !ok {
					continue
				}
				name, _ := env["name"].(string)
				// Check for secret-like env var names with direct values
				if _, hasValue := env["value"]; hasValue {
					nameLower := strings.ToLower(name)
					if containsSecretKeyword(nameLower) {
						violated = true
						break
					}
				}
			}
			if violated {
				break
			}
		}
		if violated {
			results = append(results, failResult(r, obj, "Container has secret-like environment variable with plaintext value"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

func containsSecretKeyword(name string) bool {
	keywords := []string{"password", "passwd", "secret", "token", "api_key", "apikey", "private_key", "credential"}
	for _, kw := range keywords {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

// ---- CV4012: Secrets must not be present in Pod command args ----

type cv4012Rule struct{}

func (r cv4012Rule) ID() string               { return "CV4012" }
func (r cv4012Rule) CISRef() string           { return "CIS 5.4.2" }
func (r cv4012Rule) Section() rules.CISSection { return rules.SectionPolicies }
func (r cv4012Rule) Severity() rules.Severity  { return rules.SeverityMedium }
func (r cv4012Rule) Description() string {
	return "Secrets must not be passed as command arguments"
}
func (r cv4012Rule) Remediation() string {
	return "Use Kubernetes Secrets or ConfigMaps and reference them via env vars with secretKeyRef"
}
func (r cv4012Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := getWorkloadObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		podSpec := getPodTemplateSpec(obj)
		violated := false
		for _, c := range getAllContainers(podSpec) {
			for _, field := range []string{"command", "args"} {
				argList, _ := c[field].([]interface{})
				for _, arg := range argList {
					s, _ := arg.(string)
					sLower := strings.ToLower(s)
					if looksLikeSecretArg(sLower) {
						violated = true
						break
					}
				}
				if violated {
					break
				}
			}
			if violated {
				break
			}
		}
		if violated {
			results = append(results, failResult(r, obj, "Container command/args may contain secret values"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

func looksLikeSecretArg(s string) bool {
	keywords := []string{"--password=", "--passwd=", "--token=", "--secret=", "--api-key=", "--private-key="}
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// suppress unused import warning
var _ = parser.K8sObject{}
