// Package section5 implements NSA/CISA Kubernetes Hardening Guide rules (CV5xxx).
package section5

import (
	"fmt"
	"strings"

	"github.com/ComplianceVet/compliancevet/internal/parser"
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

const (
	standard    = "NSA/CISA"
	standardRef = "NSA/CISA Kubernetes Hardening Guide v1.2 (2022)"
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

func getWorkloadObjects(objects []parser.K8sObject) []parser.K8sObject {
	var result []parser.K8sObject
	for _, obj := range objects {
		switch obj.Kind {
		case "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet":
			result = append(result, obj)
		}
	}
	return result
}

func getPodTemplateSpec(obj parser.K8sObject) map[string]interface{} {
	if obj.Kind == "Pod" {
		return obj.Spec
	}
	if tmpl, ok := obj.Spec["template"].(map[string]interface{}); ok {
		if spec, ok := tmpl["spec"].(map[string]interface{}); ok {
			return spec
		}
	}
	if jobTmpl, ok := obj.Spec["jobTemplate"].(map[string]interface{}); ok {
		if jSpec, ok := jobTmpl["spec"].(map[string]interface{}); ok {
			if tmpl, ok := jSpec["template"].(map[string]interface{}); ok {
				if spec, ok := tmpl["spec"].(map[string]interface{}); ok {
					return spec
				}
			}
		}
	}
	return obj.Spec
}

func getAllContainers(podSpec map[string]interface{}) []map[string]interface{} {
	var result []map[string]interface{}
	for _, field := range []string{"containers", "initContainers"} {
		if cs, ok := podSpec[field].([]interface{}); ok {
			for _, c := range cs {
				if cm, ok := c.(map[string]interface{}); ok {
					result = append(result, cm)
				}
			}
		}
	}
	return result
}

func getSecurityContext(container map[string]interface{}) map[string]interface{} {
	sc, _ := container["securityContext"].(map[string]interface{})
	return sc
}

func getPodSecurityContext(podSpec map[string]interface{}) map[string]interface{} {
	sc, _ := podSpec["securityContext"].(map[string]interface{})
	return sc
}

// ---- CV5001: readOnlyRootFilesystem=true ----

type cv5001Rule struct{}

func (r cv5001Rule) ID() string               { return "CV5001" }
func (r cv5001Rule) CISRef() string           { return standard + " §6.2" }
func (r cv5001Rule) Section() rules.CISSection { return rules.SectionNSACISA }
func (r cv5001Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv5001Rule) Description() string {
	return "Container root filesystem must be read-only (immutable)"
}
func (r cv5001Rule) Remediation() string {
	return "Set securityContext.readOnlyRootFilesystem=true on each container"
}
func (r cv5001Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := getWorkloadObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		podSpec := getPodTemplateSpec(obj)
		allOK := true
		for _, c := range getAllContainers(podSpec) {
			sc := getSecurityContext(c)
			if sc == nil {
				allOK = false
				break
			}
			if v, ok := sc["readOnlyRootFilesystem"].(bool); !ok || !v {
				allOK = false
				break
			}
		}
		if allOK {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "Container(s) do not use readOnlyRootFilesystem"))
		}
	}
	return results
}

// ---- CV5002: drop ALL Linux capabilities ----

type cv5002Rule struct{}

func (r cv5002Rule) ID() string               { return "CV5002" }
func (r cv5002Rule) CISRef() string           { return standard + " §6.2" }
func (r cv5002Rule) Section() rules.CISSection { return rules.SectionNSACISA }
func (r cv5002Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv5002Rule) Description() string {
	return "Container capabilities must drop ALL unnecessary Linux capabilities"
}
func (r cv5002Rule) Remediation() string {
	return "Set securityContext.capabilities.drop=[\"ALL\"] on each container"
}
func (r cv5002Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := getWorkloadObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		podSpec := getPodTemplateSpec(obj)
		allDropAll := true
		for _, c := range getAllContainers(podSpec) {
			sc := getSecurityContext(c)
			if sc == nil {
				allDropAll = false
				break
			}
			caps, ok := sc["capabilities"].(map[string]interface{})
			if !ok {
				allDropAll = false
				break
			}
			drop, ok := caps["drop"].([]interface{})
			if !ok || !sliceContainsString(drop, "ALL") {
				allDropAll = false
				break
			}
		}
		if allDropAll {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "Container(s) do not drop ALL Linux capabilities"))
		}
	}
	return results
}

// ---- CV5003: seccomp profile configured ----

type cv5003Rule struct{}

func (r cv5003Rule) ID() string               { return "CV5003" }
func (r cv5003Rule) CISRef() string           { return standard + " §6.2" }
func (r cv5003Rule) Section() rules.CISSection { return rules.SectionNSACISA }
func (r cv5003Rule) Severity() rules.Severity  { return rules.SeverityMedium }
func (r cv5003Rule) Description() string       { return "Seccomp profile must be configured for workloads" }
func (r cv5003Rule) Remediation() string {
	return "Set securityContext.seccompProfile.type=RuntimeDefault or Localhost on pod or container"
}
func (r cv5003Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := getWorkloadObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		podSpec := getPodTemplateSpec(obj)
		podSC := getPodSecurityContext(podSpec)

		// Check pod-level seccomp
		if podSC != nil {
			if profile, ok := podSC["seccompProfile"].(map[string]interface{}); ok {
				if t, ok := profile["type"].(string); ok && t != "Unconfined" && t != "" {
					results = append(results, passResult(r, obj))
					continue
				}
			}
		}

		// Check container-level seccomp
		hasSeccomp := false
		for _, c := range getAllContainers(podSpec) {
			sc := getSecurityContext(c)
			if sc == nil {
				continue
			}
			if profile, ok := sc["seccompProfile"].(map[string]interface{}); ok {
				if t, ok := profile["type"].(string); ok && t != "Unconfined" && t != "" {
					hasSeccomp = true
				}
			}
		}

		// Check annotations (older k8s)
		if !hasSeccomp {
			for k, v := range obj.Annotations {
				if strings.Contains(k, "seccomp") {
					if v != "unconfined" && v != "" {
						hasSeccomp = true
					}
				}
			}
		}

		if hasSeccomp {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, warnResult(r, obj, "No seccomp profile configured"))
		}
	}
	return results
}

// ---- CV5004: AppArmor profile configured ----

type cv5004Rule struct{}

func (r cv5004Rule) ID() string               { return "CV5004" }
func (r cv5004Rule) CISRef() string           { return standard + " §6.2" }
func (r cv5004Rule) Section() rules.CISSection { return rules.SectionNSACISA }
func (r cv5004Rule) Severity() rules.Severity  { return rules.SeverityLow }
func (r cv5004Rule) Description() string       { return "AppArmor profile should be configured for containers" }
func (r cv5004Rule) Remediation() string {
	return "Add annotation container.apparmor.security.beta.kubernetes.io/<container>=runtime/default"
}
func (r cv5004Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := getWorkloadObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		hasAppArmor := false
		for k, v := range obj.Annotations {
			if strings.Contains(k, "apparmor") {
				s := fmt.Sprintf("%v", v)
				if s != "unconfined" && s != "" {
					hasAppArmor = true
					break
				}
			}
		}
		// Also check securityContext.appArmorProfile (k8s 1.30+)
		podSpec := getPodTemplateSpec(obj)
		podSC := getPodSecurityContext(podSpec)
		if podSC != nil {
			if _, ok := podSC["appArmorProfile"]; ok {
				hasAppArmor = true
			}
		}
		if hasAppArmor {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, warnResult(r, obj, "No AppArmor profile configured"))
		}
	}
	return results
}

func sliceContainsString(slice []interface{}, val string) bool {
	for _, v := range slice {
		if s, ok := v.(string); ok && strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}
