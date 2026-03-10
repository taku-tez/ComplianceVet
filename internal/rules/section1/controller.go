package section1

import (
	"strings"

	"github.com/ComplianceVet/compliancevet/internal/parser"
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

func findControllerManagerObjects(objects []parser.K8sObject) []parser.K8sObject {
	var result []parser.K8sObject
	for _, obj := range objects {
		if obj.Kind != "Pod" {
			continue
		}
		if strings.Contains(strings.ToLower(obj.Name), "controller-manager") ||
			strings.Contains(strings.ToLower(obj.Name), "controller") {
			result = append(result, obj)
			continue
		}
		for _, c := range getContainers(obj.Spec) {
			image, _ := c["image"].(string)
			if strings.Contains(strings.ToLower(image), "kube-controller-manager") {
				result = append(result, obj)
				break
			}
		}
	}
	return result
}

func findSchedulerObjects(objects []parser.K8sObject) []parser.K8sObject {
	var result []parser.K8sObject
	for _, obj := range objects {
		if obj.Kind != "Pod" {
			continue
		}
		if strings.Contains(strings.ToLower(obj.Name), "scheduler") {
			result = append(result, obj)
			continue
		}
		for _, c := range getContainers(obj.Spec) {
			image, _ := c["image"].(string)
			if strings.Contains(strings.ToLower(image), "kube-scheduler") {
				result = append(result, obj)
				break
			}
		}
	}
	return result
}

func getFirstContainerFlags(obj parser.K8sObject) (map[string]string, bool) {
	containers := getContainers(obj.Spec)
	if len(containers) == 0 {
		return nil, false
	}
	return parseContainerFlags(containers[0]), true
}

// ---- CV1011: Controller Manager --use-service-account-credentials=true ----

type cv1011Rule struct{}

func (r cv1011Rule) ID() string               { return "CV1011" }
func (r cv1011Rule) CISRef() string           { return "CIS 1.3.2" }
func (r cv1011Rule) Section() rules.CISSection { return rules.SectionControlPlane }
func (r cv1011Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv1011Rule) Description() string {
	return "Controller Manager must use service account credentials"
}
func (r cv1011Rule) Remediation() string {
	return "Set --use-service-account-credentials=true in kube-controller-manager arguments"
}
func (r cv1011Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findControllerManagerObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getFirstContainerFlags(obj)
		if !ok {
			continue
		}
		if flagEquals(flags, "--use-service-account-credentials", "true") {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "--use-service-account-credentials is not set to true"))
		}
	}
	return results
}

// ---- CV1012: Controller Manager RotateKubeletServerCertificate feature gate ----

type cv1012Rule struct{}

func (r cv1012Rule) ID() string               { return "CV1012" }
func (r cv1012Rule) CISRef() string           { return "CIS 1.3.6" }
func (r cv1012Rule) Section() rules.CISSection { return rules.SectionControlPlane }
func (r cv1012Rule) Severity() rules.Severity  { return rules.SeverityMedium }
func (r cv1012Rule) Description() string {
	return "Controller Manager must enable RotateKubeletServerCertificate feature gate"
}
func (r cv1012Rule) Remediation() string {
	return "Add RotateKubeletServerCertificate=true to --feature-gates in kube-controller-manager"
}
func (r cv1012Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findControllerManagerObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getFirstContainerFlags(obj)
		if !ok {
			continue
		}
		fg, hasFG := flags["--feature-gates"]
		if !hasFG {
			// feature gate not set — default depends on k8s version, warn
			results = append(results, warnResult(r, obj, "--feature-gates not set; ensure RotateKubeletServerCertificate=true"))
			continue
		}
		disabled := false
		for _, gate := range strings.Split(fg, ",") {
			gate = strings.TrimSpace(gate)
			if gate == "RotateKubeletServerCertificate=false" {
				disabled = true
				break
			}
		}
		if disabled {
			results = append(results, failResult(r, obj, "RotateKubeletServerCertificate is explicitly disabled"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

// ---- CV1013: Scheduler --profiling=false ----

type cv1013Rule struct{}

func (r cv1013Rule) ID() string               { return "CV1013" }
func (r cv1013Rule) CISRef() string           { return "CIS 1.4.1" }
func (r cv1013Rule) Section() rules.CISSection { return rules.SectionControlPlane }
func (r cv1013Rule) Severity() rules.Severity  { return rules.SeverityLow }
func (r cv1013Rule) Description() string       { return "Scheduler profiling must be disabled" }
func (r cv1013Rule) Remediation() string {
	return "Set --profiling=false in kube-scheduler arguments"
}
func (r cv1013Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findSchedulerObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getFirstContainerFlags(obj)
		if !ok {
			continue
		}
		if flagEquals(flags, "--profiling", "false") {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, warnResult(r, obj, "--profiling is not set to false"))
		}
	}
	return results
}
