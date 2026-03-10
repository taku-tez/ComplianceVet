// Package section6 implements PCI-DSS v4.0 Kubernetes compliance rules (CV6xxx).
package section6

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ComplianceVet/compliancevet/internal/parser"
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

const standard = "PCI-DSS v4.0"

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

// ---- CV6001: PCI-DSS Req 2 - No default service account usage with broad permissions ----

type cv6001Rule struct{}

func (r cv6001Rule) ID() string               { return "CV6001" }
func (r cv6001Rule) CISRef() string           { return standard + " Req 2.2" }
func (r cv6001Rule) Section() rules.CISSection { return rules.SectionPCIDSS }
func (r cv6001Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv6001Rule) Description() string {
	return "PCI-DSS Req 2: Default service accounts must not have bound permissions"
}
func (r cv6001Rule) Remediation() string {
	return "Create dedicated ServiceAccounts for workloads; do not use the 'default' ServiceAccount"
}
func (r cv6001Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	// Check if any workload uses the default SA
	workloads := getWorkloadObjects(ctx.Objects)
	if len(workloads) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	// Check if 'default' SA has any RoleBindings
	defaultSABound := map[string]bool{} // namespace → true if default SA is bound
	for _, obj := range ctx.Objects {
		if obj.Kind != "RoleBinding" && obj.Kind != "ClusterRoleBinding" {
			continue
		}
		subjectsRaw, _ := obj.Raw["subjects"]
		subjects, _ := subjectsRaw.([]interface{})
		for _, s := range subjects {
			sub, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			kind, _ := sub["kind"].(string)
			name, _ := sub["name"].(string)
			namespace, _ := sub["namespace"].(string)
			if kind == "ServiceAccount" && name == "default" {
				if namespace == "" {
					namespace = "default"
				}
				defaultSABound[namespace] = true
			}
		}
	}

	var results []rules.CheckResult
	for _, obj := range workloads {
		podSpec := getPodTemplateSpec(obj)
		saName, _ := podSpec["serviceAccountName"].(string)
		ns := obj.Namespace
		if ns == "" {
			ns = "default"
		}
		if saName == "" || saName == "default" {
			if defaultSABound[ns] {
				results = append(results, failResult(r, obj, "Workload uses 'default' ServiceAccount which has bound permissions"))
			} else {
				results = append(results, warnResult(r, obj, "Workload uses 'default' ServiceAccount (consider a dedicated SA)"))
			}
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

// ---- CV6002: PCI-DSS Req 6 - Container images must not use 'latest' tag ----

type cv6002Rule struct{}

func (r cv6002Rule) ID() string               { return "CV6002" }
func (r cv6002Rule) CISRef() string           { return standard + " Req 6.3" }
func (r cv6002Rule) Section() rules.CISSection { return rules.SectionPCIDSS }
func (r cv6002Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv6002Rule) Description() string {
	return "PCI-DSS Req 6: Container images must use specific, pinned version tags"
}
func (r cv6002Rule) Remediation() string {
	return "Replace 'latest' or untagged images with specific version tags (e.g., nginx:1.25.3)"
}
func (r cv6002Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := getWorkloadObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		podSpec := getPodTemplateSpec(obj)
		violated := false
		for _, c := range getAllContainers(podSpec) {
			image, _ := c["image"].(string)
			if imageUsesLatestOrUnpinned(image) {
				violated = true
				break
			}
		}
		if violated {
			results = append(results, failResult(r, obj, "Container uses 'latest' or unpinned image tag"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

func imageUsesLatestOrUnpinned(image string) bool {
	if image == "" {
		return false
	}
	// Remove registry prefix
	parts := strings.SplitN(image, "/", 3)
	lastPart := parts[len(parts)-1]
	// If no colon, it's an implicit 'latest'
	if !strings.Contains(lastPart, ":") {
		return true
	}
	tag := strings.SplitN(lastPart, ":", 2)[1]
	if tag == "" || tag == "latest" {
		return true
	}
	// SHA digest pins are OK
	if strings.HasPrefix(tag, "sha256:") {
		return false
	}
	return false
}

// ---- CV6003: PCI-DSS Req 7 - RBAC least privilege (no cluster-admin for workloads) ----

type cv6003Rule struct{}

func (r cv6003Rule) ID() string               { return "CV6003" }
func (r cv6003Rule) CISRef() string           { return standard + " Req 7.2" }
func (r cv6003Rule) Section() rules.CISSection { return rules.SectionPCIDSS }
func (r cv6003Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv6003Rule) Description() string {
	return "PCI-DSS Req 7: Workload ServiceAccounts must not have cluster-admin binding"
}
func (r cv6003Rule) Remediation() string {
	return "Remove cluster-admin ClusterRoleBinding from workload ServiceAccounts; use least-privilege roles"
}
func (r cv6003Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	// Build set of SAs used by workloads in non-system namespaces
	workloadSAs := map[string]bool{} // "namespace/saname"
	for _, obj := range getWorkloadObjects(ctx.Objects) {
		ns := obj.Namespace
		if ns == "" {
			ns = "default"
		}
		if ns == "kube-system" || ns == "kube-public" {
			continue
		}
		podSpec := getPodTemplateSpec(obj)
		saName, _ := podSpec["serviceAccountName"].(string)
		if saName == "" {
			saName = "default"
		}
		workloadSAs[ns+"/"+saName] = true
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
		name, _ := roleRef["name"].(string)
		if name != "cluster-admin" {
			results = append(results, passResult(r, obj))
			continue
		}
		subjectsRaw, _ := obj.Raw["subjects"]
		subjects, _ := subjectsRaw.([]interface{})
		violated := false
		for _, s := range subjects {
			sub, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			kind, _ := sub["kind"].(string)
			subName, _ := sub["name"].(string)
			subNS, _ := sub["namespace"].(string)
			if kind == "ServiceAccount" && workloadSAs[subNS+"/"+subName] {
				violated = true
				break
			}
		}
		if violated {
			results = append(results, failResult(r, obj, "Workload ServiceAccount has cluster-admin binding"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

// ---- CV6004: PCI-DSS Req 8 - No anonymous authentication ----

type cv6004Rule struct{}

func (r cv6004Rule) ID() string               { return "CV6004" }
func (r cv6004Rule) CISRef() string           { return standard + " Req 8.2" }
func (r cv6004Rule) Section() rules.CISSection { return rules.SectionPCIDSS }
func (r cv6004Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv6004Rule) Description() string {
	return "PCI-DSS Req 8: Anonymous authentication must be disabled on the API server"
}
func (r cv6004Rule) Remediation() string {
	return "Set --anonymous-auth=false on kube-apiserver"
}
func (r cv6004Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
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
		flags := getAPIServerFlags(obj)
		if strings.EqualFold(flags["--anonymous-auth"], "false") {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "--anonymous-auth is not false; anonymous access is allowed"))
		}
	}
	return results
}

// ---- CV6005: PCI-DSS Req 10 - Audit log retention >= 1 year ----

type cv6005Rule struct{}

func (r cv6005Rule) ID() string               { return "CV6005" }
func (r cv6005Rule) CISRef() string           { return standard + " Req 10.5" }
func (r cv6005Rule) Section() rules.CISSection { return rules.SectionPCIDSS }
func (r cv6005Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv6005Rule) Description() string {
	return "PCI-DSS Req 10: Audit logs must be retained for at least 365 days"
}
func (r cv6005Rule) Remediation() string {
	return "Set --audit-log-maxage=365 or greater on kube-apiserver"
}
func (r cv6005Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
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
		flags := getAPIServerFlags(obj)
		v, ok := flags["--audit-log-maxage"]
		if !ok || v == "" {
			results = append(results, failResult(r, obj, "--audit-log-maxage is not set (must be >= 365 for PCI-DSS)"))
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 365 {
			results = append(results, failResult(r, obj,
				fmt.Sprintf("--audit-log-maxage=%s is below PCI-DSS requirement of 365 days", v)))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

// ---- CV6006: PCI-DSS Req 10 - Audit logging must be enabled ----

type cv6006Rule struct{}

func (r cv6006Rule) ID() string               { return "CV6006" }
func (r cv6006Rule) CISRef() string           { return standard + " Req 10.2" }
func (r cv6006Rule) Section() rules.CISSection { return rules.SectionPCIDSS }
func (r cv6006Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv6006Rule) Description() string {
	return "PCI-DSS Req 10: Kubernetes audit logging must be enabled"
}
func (r cv6006Rule) Remediation() string {
	return "Configure --audit-log-path and --audit-policy-file on the API server"
}
func (r cv6006Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
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
		flags := getAPIServerFlags(obj)
		if flags["--audit-log-path"] != "" {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "Audit logging is not configured (--audit-log-path missing)"))
		}
	}
	return results
}

// ---- CV6007: PCI-DSS Req 11 - CDE namespaces must have NetworkPolicy ----

type cv6007Rule struct{}

func (r cv6007Rule) ID() string               { return "CV6007" }
func (r cv6007Rule) CISRef() string           { return standard + " Req 11.4" }
func (r cv6007Rule) Section() rules.CISSection { return rules.SectionPCIDSS }
func (r cv6007Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv6007Rule) Description() string {
	return "PCI-DSS Req 11: Cardholder Data Environment namespaces must be isolated with NetworkPolicy"
}
func (r cv6007Rule) Remediation() string {
	return "Create restrictive NetworkPolicies in namespaces that handle cardholder data"
}
func (r cv6007Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	// Identify CDE namespaces by labels/annotations
	cdeNamespaces := map[string]parser.K8sObject{}
	for _, obj := range ctx.Objects {
		if obj.Kind != "Namespace" {
			continue
		}
		if isCDENamespace(obj) {
			cdeNamespaces[obj.Name] = obj
		}
	}

	// If no labeled CDE namespaces, check by name convention
	if len(cdeNamespaces) == 0 {
		for _, obj := range ctx.Objects {
			if obj.Kind != "Namespace" {
				continue
			}
			nameLower := strings.ToLower(obj.Name)
			if strings.Contains(nameLower, "payment") || strings.Contains(nameLower, "card") ||
				strings.Contains(nameLower, "pci") || strings.Contains(nameLower, "cde") {
				cdeNamespaces[obj.Name] = obj
			}
		}
	}

	if len(cdeNamespaces) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}

	// Check which CDE namespaces have NetworkPolicies
	coveredNS := map[string]bool{}
	for _, obj := range ctx.Objects {
		if obj.Kind == "NetworkPolicy" {
			ns := obj.Namespace
			if ns == "" {
				ns = "default"
			}
			coveredNS[ns] = true
		}
	}

	var results []rules.CheckResult
	for ns, nsObj := range cdeNamespaces {
		if coveredNS[ns] {
			results = append(results, passResult(r, nsObj))
		} else {
			results = append(results, failResult(r, nsObj, "CDE Namespace has no NetworkPolicy for isolation"))
		}
	}
	return results
}

func isCDENamespace(obj parser.K8sObject) bool {
	for k, v := range obj.Labels {
		if strings.Contains(k, "pci") || strings.Contains(k, "cde") ||
			strings.Contains(strings.ToLower(v), "pci") || strings.Contains(strings.ToLower(v), "cde") {
			return true
		}
	}
	for k := range obj.Annotations {
		if strings.Contains(k, "pci") || strings.Contains(k, "cde") {
			return true
		}
	}
	return false
}

// ---- CV6008: PCI-DSS Req 2 - No privileged containers ----

type cv6008Rule struct{}

func (r cv6008Rule) ID() string               { return "CV6008" }
func (r cv6008Rule) CISRef() string           { return standard + " Req 2.2" }
func (r cv6008Rule) Section() rules.CISSection { return rules.SectionPCIDSS }
func (r cv6008Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv6008Rule) Description() string {
	return "PCI-DSS Req 2: Privileged containers must not be used in CDE workloads"
}
func (r cv6008Rule) Remediation() string {
	return "Set securityContext.privileged=false or remove the privileged flag"
}
func (r cv6008Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := getWorkloadObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		podSpec := getPodTemplateSpec(obj)
		violated := false
		for _, c := range getAllContainers(podSpec) {
			sc, _ := c["securityContext"].(map[string]interface{})
			if sc == nil {
				continue
			}
			if v, ok := sc["privileged"].(bool); ok && v {
				violated = true
				break
			}
		}
		if violated {
			results = append(results, failResult(r, obj, "Container runs in privileged mode (PCI-DSS violation)"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

func getAPIServerFlags(obj parser.K8sObject) map[string]string {
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

// suppress unused import
var _ = strconv.Atoi
