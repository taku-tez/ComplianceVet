package section4

import (
	"github.com/ComplianceVet/compliancevet/internal/parser"
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

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

// getPodTemplateSpec returns the pod template spec for any workload type.
func getPodTemplateSpec(obj parser.K8sObject) map[string]interface{} {
	if obj.Kind == "Pod" {
		return obj.Spec
	}
	// For Deployment/StatefulSet/DaemonSet: spec.template.spec
	if tmpl, ok := obj.Spec["template"].(map[string]interface{}); ok {
		if spec, ok := tmpl["spec"].(map[string]interface{}); ok {
			return spec
		}
	}
	// For CronJob: spec.jobTemplate.spec.template.spec
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
	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
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

// ---- CV4005: Pods must run as non-root ----

type cv4005Rule struct{}

func (r cv4005Rule) ID() string               { return "CV4005" }
func (r cv4005Rule) CISRef() string           { return "CIS 5.2.6" }
func (r cv4005Rule) Section() rules.CISSection { return rules.SectionPolicies }
func (r cv4005Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv4005Rule) Description() string       { return "Containers must not run as root" }
func (r cv4005Rule) Remediation() string {
	return "Set securityContext.runAsNonRoot=true or securityContext.runAsUser to a non-zero value"
}
func (r cv4005Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := getWorkloadObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		podSpec := getPodTemplateSpec(obj)
		podSC := getPodSecurityContext(podSpec)

		podLevelOK := false
		if podSC != nil {
			if v, ok := podSC["runAsNonRoot"].(bool); ok && v {
				podLevelOK = true
			}
			if uid, ok := podSC["runAsUser"]; ok {
				if uidInt, ok := uid.(int); ok && uidInt > 0 {
					podLevelOK = true
				}
				if uidFloat, ok := uid.(float64); ok && uidFloat > 0 {
					podLevelOK = true
				}
			}
		}

		violated := false
		for _, c := range getAllContainers(podSpec) {
			if podLevelOK {
				break
			}
			sc := getSecurityContext(c)
			if sc == nil {
				violated = true
				break
			}
			runAsNonRoot, hasRNR := sc["runAsNonRoot"].(bool)
			if hasRNR && runAsNonRoot {
				continue
			}
			runAsUser := sc["runAsUser"]
			if runAsUser != nil {
				if uid, ok := runAsUser.(int); ok && uid > 0 {
					continue
				}
				if uid, ok := runAsUser.(float64); ok && uid > 0 {
					continue
				}
			}
			violated = true
		}

		if violated {
			results = append(results, failResult(r, obj, "Container(s) may run as root; runAsNonRoot not set"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

// ---- CV4006: No privileged containers ----

type cv4006Rule struct{}

func (r cv4006Rule) ID() string               { return "CV4006" }
func (r cv4006Rule) CISRef() string           { return "CIS 5.2.1" }
func (r cv4006Rule) Section() rules.CISSection { return rules.SectionPolicies }
func (r cv4006Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv4006Rule) Description() string       { return "Privileged containers must not be used" }
func (r cv4006Rule) Remediation() string {
	return "Set securityContext.privileged=false or remove the privileged field"
}
func (r cv4006Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := getWorkloadObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		podSpec := getPodTemplateSpec(obj)
		violated := false
		for _, c := range getAllContainers(podSpec) {
			sc := getSecurityContext(c)
			if sc == nil {
				continue
			}
			if v, ok := sc["privileged"].(bool); ok && v {
				violated = true
				break
			}
		}
		if violated {
			results = append(results, failResult(r, obj, "Container runs in privileged mode"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

// ---- CV4007: No hostPID usage ----

type cv4007Rule struct{}

func (r cv4007Rule) ID() string               { return "CV4007" }
func (r cv4007Rule) CISRef() string           { return "CIS 5.2.2" }
func (r cv4007Rule) Section() rules.CISSection { return rules.SectionPolicies }
func (r cv4007Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv4007Rule) Description() string       { return "Pods must not share the host process ID namespace" }
func (r cv4007Rule) Remediation() string {
	return "Remove or set hostPID: false in the pod spec"
}
func (r cv4007Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := getWorkloadObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		podSpec := getPodTemplateSpec(obj)
		if v, ok := podSpec["hostPID"].(bool); ok && v {
			results = append(results, failResult(r, obj, "Pod uses hostPID: true"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

// ---- CV4008: No hostIPC usage ----

type cv4008Rule struct{}

func (r cv4008Rule) ID() string               { return "CV4008" }
func (r cv4008Rule) CISRef() string           { return "CIS 5.2.3" }
func (r cv4008Rule) Section() rules.CISSection { return rules.SectionPolicies }
func (r cv4008Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv4008Rule) Description() string       { return "Pods must not share the host IPC namespace" }
func (r cv4008Rule) Remediation() string {
	return "Remove or set hostIPC: false in the pod spec"
}
func (r cv4008Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := getWorkloadObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		podSpec := getPodTemplateSpec(obj)
		if v, ok := podSpec["hostIPC"].(bool); ok && v {
			results = append(results, failResult(r, obj, "Pod uses hostIPC: true"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

// ---- CV4009: No hostNetwork usage ----

type cv4009Rule struct{}

func (r cv4009Rule) ID() string               { return "CV4009" }
func (r cv4009Rule) CISRef() string           { return "CIS 5.2.4" }
func (r cv4009Rule) Section() rules.CISSection { return rules.SectionPolicies }
func (r cv4009Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv4009Rule) Description() string       { return "Pods must not use the host network" }
func (r cv4009Rule) Remediation() string {
	return "Remove or set hostNetwork: false in the pod spec"
}
func (r cv4009Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := getWorkloadObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		podSpec := getPodTemplateSpec(obj)
		if v, ok := podSpec["hostNetwork"].(bool); ok && v {
			results = append(results, failResult(r, obj, "Pod uses hostNetwork: true"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}
