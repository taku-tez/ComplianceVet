package section5

import (
	"strings"

	"github.com/ComplianceVet/compliancevet/internal/parser"
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

// ---- CV5009: No cluster-admin ClusterRoleBinding for non-system accounts ----

type cv5009Rule struct{}

func (r cv5009Rule) ID() string               { return "CV5009" }
func (r cv5009Rule) CISRef() string           { return standard + " §8.1" }
func (r cv5009Rule) Section() rules.CISSection { return rules.SectionNSACISA }
func (r cv5009Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv5009Rule) Description() string {
	return "cluster-admin ClusterRoleBinding must not be granted to non-system accounts"
}
func (r cv5009Rule) Remediation() string {
	return "Remove cluster-admin ClusterRoleBinding for non-system service accounts and users; grant least-privilege roles instead"
}
func (r cv5009Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	var bindings []parser.K8sObject
	for _, obj := range ctx.Objects {
		if obj.Kind == "ClusterRoleBinding" {
			bindings = append(bindings, obj)
		}
	}
	if len(bindings) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range bindings {
		// Check if roleRef is cluster-admin
		roleRef, _ := obj.Raw["roleRef"].(map[string]interface{})
		name, _ := roleRef["name"].(string)
		if name != "cluster-admin" {
			results = append(results, passResult(r, obj))
			continue
		}
		// Check subjects for non-system accounts
		subjectsRaw, _ := obj.Raw["subjects"]
		subjects, _ := subjectsRaw.([]interface{})
		hasNonSystem := false
		for _, s := range subjects {
			sub, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			kind, _ := sub["kind"].(string)
			subName, _ := sub["name"].(string)
			subNS, _ := sub["namespace"].(string)
			// System subjects are OK
			if isSystemSubject(kind, subName, subNS) {
				continue
			}
			hasNonSystem = true
			break
		}
		if hasNonSystem {
			results = append(results, failResult(r, obj, "cluster-admin ClusterRoleBinding granted to non-system account"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

func isSystemSubject(kind, name, namespace string) bool {
	if strings.HasPrefix(name, "system:") {
		return true
	}
	if namespace == "kube-system" {
		return true
	}
	return false
}

// ---- CV5010: ServiceAccount token must not be auto-mounted in user workloads ----

type cv5010Rule struct{}

func (r cv5010Rule) ID() string               { return "CV5010" }
func (r cv5010Rule) CISRef() string           { return standard + " §8.2" }
func (r cv5010Rule) Section() rules.CISSection { return rules.SectionNSACISA }
func (r cv5010Rule) Severity() rules.Severity  { return rules.SeverityMedium }
func (r cv5010Rule) Description() string {
	return "Workloads that do not need API access must disable ServiceAccount token auto-mounting"
}
func (r cv5010Rule) Remediation() string {
	return "Set automountServiceAccountToken: false in Pod spec or ServiceAccount"
}
func (r cv5010Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := getWorkloadObjects(ctx.Objects)
	var userWorkloads []parser.K8sObject
	for _, obj := range objs {
		ns := obj.Namespace
		if ns == "kube-system" || ns == "kube-public" {
			continue
		}
		userWorkloads = append(userWorkloads, obj)
	}
	if len(userWorkloads) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}

	// Build map of ServiceAccounts with automountServiceAccountToken=false
	saNoAutoMount := map[string]bool{}
	for _, obj := range ctx.Objects {
		if obj.Kind != "ServiceAccount" {
			continue
		}
		v, ok := obj.Raw["automountServiceAccountToken"]
		if ok {
			if b, isBool := v.(bool); isBool && !b {
				key := obj.Namespace + "/" + obj.Name
				saNoAutoMount[key] = true
			}
		}
	}

	var results []rules.CheckResult
	for _, obj := range userWorkloads {
		podSpec := getPodTemplateSpec(obj)

		// Check pod-level automount
		if v, ok := podSpec["automountServiceAccountToken"].(bool); ok && !v {
			results = append(results, passResult(r, obj))
			continue
		}

		// Check if using a ServiceAccount with automount disabled
		saName, _ := podSpec["serviceAccountName"].(string)
		if saName == "" {
			saName = "default"
		}
		ns := obj.Namespace
		if ns == "" {
			ns = "default"
		}
		if saNoAutoMount[ns+"/"+saName] {
			results = append(results, passResult(r, obj))
			continue
		}

		results = append(results, warnResult(r, obj, "automountServiceAccountToken is not explicitly disabled"))
	}
	return results
}

// ---- CV5011: RBAC - no wildcard ClusterRoles bound to user groups ----

type cv5011Rule struct{}

func (r cv5011Rule) ID() string               { return "CV5011" }
func (r cv5011Rule) CISRef() string           { return standard + " §8.1" }
func (r cv5011Rule) Section() rules.CISSection { return rules.SectionNSACISA }
func (r cv5011Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv5011Rule) Description() string {
	return "ClusterRoles with wildcard permissions must not be bound to users or groups"
}
func (r cv5011Rule) Remediation() string {
	return "Replace wildcard-permission ClusterRoles with specific, least-privilege roles for user bindings"
}
func (r cv5011Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	// Identify ClusterRoles with wildcard verbs or resources
	wildcardRoles := map[string]bool{}
	for _, obj := range ctx.Objects {
		if obj.Kind != "ClusterRole" {
			continue
		}
		rulesRaw, _ := obj.Raw["rules"].([]interface{})
		for _, rule := range rulesRaw {
			ruleMap, ok := rule.(map[string]interface{})
			if !ok {
				continue
			}
			verbs, _ := ruleMap["verbs"].([]interface{})
			resources, _ := ruleMap["resources"].([]interface{})
			if sliceContainsStr(verbs, "*") || sliceContainsStr(resources, "*") {
				wildcardRoles[obj.Name] = true
				break
			}
		}
	}

	var bindings []parser.K8sObject
	for _, obj := range ctx.Objects {
		if obj.Kind == "ClusterRoleBinding" {
			bindings = append(bindings, obj)
		}
	}
	if len(bindings) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}

	var results []rules.CheckResult
	for _, obj := range bindings {
		roleRef, _ := obj.Raw["roleRef"].(map[string]interface{})
		roleName, _ := roleRef["name"].(string)
		if !wildcardRoles[roleName] {
			results = append(results, passResult(r, obj))
			continue
		}

		// Check if any subject is a User or Group
		subjectsRaw, _ := obj.Raw["subjects"]
		subjects, _ := subjectsRaw.([]interface{})
		hasUserGroup := false
		for _, s := range subjects {
			sub, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			kind, _ := sub["kind"].(string)
			name, _ := sub["name"].(string)
			if (kind == "User" || kind == "Group") && !strings.HasPrefix(name, "system:") {
				hasUserGroup = true
				break
			}
		}
		if hasUserGroup {
			results = append(results, failResult(r, obj, "Wildcard-permission ClusterRole bound to user/group"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

func sliceContainsStr(slice []interface{}, val string) bool {
	for _, v := range slice {
		if s, ok := v.(string); ok && s == val {
			return true
		}
	}
	return false
}
