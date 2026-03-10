package section1

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ComplianceVet/compliancevet/internal/parser"
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

// findAPIServerObjects returns all Pod objects that look like kube-apiserver static pods.
func findAPIServerObjects(objects []parser.K8sObject) []parser.K8sObject {
	var result []parser.K8sObject
	for _, obj := range objects {
		if obj.Kind != "Pod" {
			continue
		}
		if strings.Contains(strings.ToLower(obj.Name), "kube-apiserver") ||
			strings.Contains(strings.ToLower(obj.Name), "apiserver") {
			result = append(result, obj)
			continue
		}
		for _, c := range getContainers(obj.Spec) {
			image, _ := c["image"].(string)
			if strings.Contains(strings.ToLower(image), "kube-apiserver") {
				result = append(result, obj)
				break
			}
		}
	}
	return result
}

func getContainers(spec map[string]interface{}) []map[string]interface{} {
	var result []map[string]interface{}
	if cs, ok := spec["containers"].([]interface{}); ok {
		for _, c := range cs {
			if cm, ok := c.(map[string]interface{}); ok {
				result = append(result, cm)
			}
		}
	}
	return result
}

func getAPIServerFlags(obj parser.K8sObject) (map[string]string, bool) {
	for _, c := range getContainers(obj.Spec) {
		name, _ := c["name"].(string)
		image, _ := c["image"].(string)
		if strings.Contains(strings.ToLower(name), "apiserver") ||
			strings.Contains(strings.ToLower(image), "kube-apiserver") {
			return parseContainerFlags(c), true
		}
	}
	containers := getContainers(obj.Spec)
	if len(containers) > 0 {
		return parseContainerFlags(containers[0]), true
	}
	return nil, false
}

func parseContainerFlags(container map[string]interface{}) map[string]string {
	flags := map[string]string{}
	for _, field := range []string{"command", "args"} {
		if raw, ok := container[field]; ok {
			switch v := raw.(type) {
			case []interface{}:
				for _, item := range v {
					s, _ := item.(string)
					parseFlag(s, flags)
				}
			case string:
				parseFlag(v, flags)
			}
		}
	}
	return flags
}

func parseFlag(s string, out map[string]string) {
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

func flagEquals(flags map[string]string, name, expected string) bool {
	v, ok := flags[name]
	return ok && strings.EqualFold(v, expected)
}

func flagContains(flags map[string]string, name, item string) bool {
	v, ok := flags[name]
	if !ok {
		return false
	}
	for _, part := range strings.Split(v, ",") {
		if strings.TrimSpace(part) == item {
			return true
		}
	}
	return false
}

func flagIsSet(flags map[string]string, name string) bool {
	v, ok := flags[name]
	return ok && v != ""
}

func flagGte(flags map[string]string, name string, min int) bool {
	v, ok := flags[name]
	if !ok {
		return false
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return false
	}
	return n >= min
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

func resourceRef(obj parser.K8sObject) string {
	if obj.Namespace != "" {
		return fmt.Sprintf("%s/%s/%s", obj.Kind, obj.Namespace, obj.Name)
	}
	return fmt.Sprintf("%s/%s", obj.Kind, obj.Name)
}

// ---- CV1001: --anonymous-auth=false ----

type cv1001Rule struct{}

func (r cv1001Rule) ID() string               { return "CV1001" }
func (r cv1001Rule) CISRef() string           { return "CIS 1.2.1" }
func (r cv1001Rule) Section() rules.CISSection { return rules.SectionControlPlane }
func (r cv1001Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv1001Rule) Description() string {
	return "API Server anonymous authentication must be disabled"
}
func (r cv1001Rule) Remediation() string {
	return "Set --anonymous-auth=false in kube-apiserver arguments"
}
func (r cv1001Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findAPIServerObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getAPIServerFlags(obj)
		if !ok {
			continue
		}
		if flagEquals(flags, "--anonymous-auth", "false") {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "--anonymous-auth is not set to false"))
		}
	}
	return results
}

// ---- CV1002: --audit-log-path is set ----

type cv1002Rule struct{}

func (r cv1002Rule) ID() string               { return "CV1002" }
func (r cv1002Rule) CISRef() string           { return "CIS 1.2.22" }
func (r cv1002Rule) Section() rules.CISSection { return rules.SectionControlPlane }
func (r cv1002Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv1002Rule) Description() string       { return "API Server audit log path must be configured" }
func (r cv1002Rule) Remediation() string {
	return "Set --audit-log-path to a valid path in kube-apiserver arguments"
}
func (r cv1002Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findAPIServerObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getAPIServerFlags(obj)
		if !ok {
			continue
		}
		if flagIsSet(flags, "--audit-log-path") {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "--audit-log-path is not configured"))
		}
	}
	return results
}

// ---- CV1003: --audit-log-maxage >= 30 ----

type cv1003Rule struct{}

func (r cv1003Rule) ID() string               { return "CV1003" }
func (r cv1003Rule) CISRef() string           { return "CIS 1.2.23" }
func (r cv1003Rule) Section() rules.CISSection { return rules.SectionControlPlane }
func (r cv1003Rule) Severity() rules.Severity  { return rules.SeverityMedium }
func (r cv1003Rule) Description() string       { return "API Server audit log max age must be >= 30 days" }
func (r cv1003Rule) Remediation() string {
	return "Set --audit-log-maxage=30 or greater in kube-apiserver arguments"
}
func (r cv1003Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findAPIServerObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getAPIServerFlags(obj)
		if !ok {
			continue
		}
		if flagGte(flags, "--audit-log-maxage", 30) {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "--audit-log-maxage must be >= 30"))
		}
	}
	return results
}

// ---- CV1004: --audit-log-maxbackup >= 10 ----

type cv1004Rule struct{}

func (r cv1004Rule) ID() string               { return "CV1004" }
func (r cv1004Rule) CISRef() string           { return "CIS 1.2.24" }
func (r cv1004Rule) Section() rules.CISSection { return rules.SectionControlPlane }
func (r cv1004Rule) Severity() rules.Severity  { return rules.SeverityMedium }
func (r cv1004Rule) Description() string       { return "API Server audit log max backup must be >= 10" }
func (r cv1004Rule) Remediation() string {
	return "Set --audit-log-maxbackup=10 or greater in kube-apiserver arguments"
}
func (r cv1004Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findAPIServerObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getAPIServerFlags(obj)
		if !ok {
			continue
		}
		if flagGte(flags, "--audit-log-maxbackup", 10) {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "--audit-log-maxbackup must be >= 10"))
		}
	}
	return results
}

// ---- CV1005: --audit-log-maxsize >= 100 ----

type cv1005Rule struct{}

func (r cv1005Rule) ID() string               { return "CV1005" }
func (r cv1005Rule) CISRef() string           { return "CIS 1.2.25" }
func (r cv1005Rule) Section() rules.CISSection { return rules.SectionControlPlane }
func (r cv1005Rule) Severity() rules.Severity  { return rules.SeverityMedium }
func (r cv1005Rule) Description() string       { return "API Server audit log max size must be >= 100 MB" }
func (r cv1005Rule) Remediation() string {
	return "Set --audit-log-maxsize=100 or greater in kube-apiserver arguments"
}
func (r cv1005Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findAPIServerObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getAPIServerFlags(obj)
		if !ok {
			continue
		}
		if flagGte(flags, "--audit-log-maxsize", 100) {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "--audit-log-maxsize must be >= 100"))
		}
	}
	return results
}

// ---- CV1006: --authorization-mode must not include AlwaysAllow ----

type cv1006Rule struct{}

func (r cv1006Rule) ID() string               { return "CV1006" }
func (r cv1006Rule) CISRef() string           { return "CIS 1.2.7" }
func (r cv1006Rule) Section() rules.CISSection { return rules.SectionControlPlane }
func (r cv1006Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv1006Rule) Description() string {
	return "API Server authorization mode must not include AlwaysAllow"
}
func (r cv1006Rule) Remediation() string {
	return "Remove AlwaysAllow from --authorization-mode; use Node,RBAC instead"
}
func (r cv1006Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findAPIServerObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getAPIServerFlags(obj)
		if !ok {
			continue
		}
		if flagContains(flags, "--authorization-mode", "AlwaysAllow") {
			results = append(results, failResult(r, obj, "--authorization-mode includes AlwaysAllow"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

// ---- CV1007: --authorization-mode must include Node and RBAC ----

type cv1007Rule struct{}

func (r cv1007Rule) ID() string               { return "CV1007" }
func (r cv1007Rule) CISRef() string           { return "CIS 1.2.8" }
func (r cv1007Rule) Section() rules.CISSection { return rules.SectionControlPlane }
func (r cv1007Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv1007Rule) Description() string {
	return "API Server authorization mode must include Node and RBAC"
}
func (r cv1007Rule) Remediation() string {
	return "Set --authorization-mode=Node,RBAC in kube-apiserver arguments"
}
func (r cv1007Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findAPIServerObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getAPIServerFlags(obj)
		if !ok {
			continue
		}
		if flagContains(flags, "--authorization-mode", "Node") && flagContains(flags, "--authorization-mode", "RBAC") {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "--authorization-mode must include both Node and RBAC"))
		}
	}
	return results
}

// ---- CV1008: NodeRestriction admission plugin ----

type cv1008Rule struct{}

func (r cv1008Rule) ID() string               { return "CV1008" }
func (r cv1008Rule) CISRef() string           { return "CIS 1.2.16" }
func (r cv1008Rule) Section() rules.CISSection { return rules.SectionControlPlane }
func (r cv1008Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv1008Rule) Description() string {
	return "NodeRestriction admission plugin must be enabled"
}
func (r cv1008Rule) Remediation() string {
	return "Add NodeRestriction to --enable-admission-plugins in kube-apiserver arguments"
}
func (r cv1008Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findAPIServerObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getAPIServerFlags(obj)
		if !ok {
			continue
		}
		if flagContains(flags, "--enable-admission-plugins", "NodeRestriction") {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "NodeRestriction admission plugin is not enabled"))
		}
	}
	return results
}

// ---- CV1009: PodSecurity admission plugin ----

type cv1009Rule struct{}

func (r cv1009Rule) ID() string               { return "CV1009" }
func (r cv1009Rule) CISRef() string           { return "CIS 1.2.17" }
func (r cv1009Rule) Section() rules.CISSection { return rules.SectionControlPlane }
func (r cv1009Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv1009Rule) Description() string       { return "PodSecurity admission plugin must be enabled" }
func (r cv1009Rule) Remediation() string {
	return "Add PodSecurity to --enable-admission-plugins in kube-apiserver arguments"
}
func (r cv1009Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findAPIServerObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getAPIServerFlags(obj)
		if !ok {
			continue
		}
		if flagContains(flags, "--enable-admission-plugins", "PodSecurity") {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, warnResult(r, obj, "PodSecurity admission plugin is not enabled"))
		}
	}
	return results
}

// ---- CV1010: TLS cert and key must be set ----

type cv1010Rule struct{}

func (r cv1010Rule) ID() string               { return "CV1010" }
func (r cv1010Rule) CISRef() string           { return "CIS 1.2.29" }
func (r cv1010Rule) Section() rules.CISSection { return rules.SectionControlPlane }
func (r cv1010Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv1010Rule) Description() string {
	return "API Server TLS certificate and private key must be configured"
}
func (r cv1010Rule) Remediation() string {
	return "Set --tls-cert-file and --tls-private-key-file in kube-apiserver arguments"
}
func (r cv1010Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findAPIServerObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getAPIServerFlags(obj)
		if !ok {
			continue
		}
		if flagIsSet(flags, "--tls-cert-file") && flagIsSet(flags, "--tls-private-key-file") {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "--tls-cert-file and/or --tls-private-key-file are not set"))
		}
	}
	return results
}
