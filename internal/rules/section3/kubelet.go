package section3

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ComplianceVet/compliancevet/internal/parser"
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

// findKubeletConfigObjects returns KubeletConfiguration ConfigMaps or standalone YAML.
// Also returns Pod objects running kubelet.
func findKubeletConfigObjects(objects []parser.K8sObject) []parser.K8sObject {
	var result []parser.K8sObject
	for _, obj := range objects {
		switch obj.Kind {
		case "KubeletConfiguration":
			result = append(result, obj)
		case "ConfigMap":
			// Look for kubelet config embedded in a ConfigMap
			if strings.Contains(strings.ToLower(obj.Name), "kubelet") {
				result = append(result, obj)
			}
		case "Pod":
			if strings.Contains(strings.ToLower(obj.Name), "kubelet") {
				result = append(result, obj)
			}
			for _, c := range getContainers(obj.Spec) {
				image, _ := c["image"].(string)
				if strings.Contains(strings.ToLower(image), "kubelet") {
					result = append(result, obj)
					break
				}
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

// getKubeletConfigValue retrieves a value from a KubeletConfiguration object or raw spec.
// For KubeletConfiguration kind, the fields are at the top level of Spec/Raw.
func getKubeletConfigBool(obj parser.K8sObject, keys ...string) (bool, bool) {
	// Try spec first
	var cur interface{} = obj.Spec
	return getNestedBool(cur, keys...)
}

func getNestedBool(cur interface{}, keys ...string) (bool, bool) {
	m, ok := cur.(map[string]interface{})
	if !ok {
		return false, false
	}
	if len(keys) == 1 {
		v, ok := m[keys[0]]
		if !ok {
			return false, false
		}
		b, ok := v.(bool)
		return b, ok
	}
	next, ok := m[keys[0]]
	if !ok {
		return false, false
	}
	return getNestedBool(next, keys[1:]...)
}

func getNestedString(cur interface{}, keys ...string) (string, bool) {
	m, ok := cur.(map[string]interface{})
	if !ok {
		return "", false
	}
	if len(keys) == 1 {
		v, ok := m[keys[0]]
		if !ok {
			return "", false
		}
		s, ok := v.(string)
		return s, ok
	}
	next, ok := m[keys[0]]
	if !ok {
		return "", false
	}
	return getNestedString(next, keys[1:]...)
}

func flagEquals(flags map[string]string, name, expected string) bool {
	v, ok := flags[name]
	return ok && strings.EqualFold(v, expected)
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

// checkKubeletAnonymousAuth checks both KubeletConfiguration YAML and Pod flags.
func checkKubeletAnonymousAuth(obj parser.K8sObject) (bool, string) {
	if obj.Kind == "KubeletConfiguration" {
		b, ok := getKubeletConfigBool(obj, "authentication", "anonymous", "enabled")
		if ok {
			return !b, fmt.Sprintf("authentication.anonymous.enabled=%v", b)
		}
		// Not set — anonymous auth defaults to enabled in older versions, warn
		return false, "authentication.anonymous.enabled not set"
	}
	if obj.Kind == "Pod" {
		for _, c := range getContainers(obj.Spec) {
			flags := parseContainerFlags(c)
			if flagEquals(flags, "--anonymous-auth", "false") {
				return true, ""
			}
			if _, ok := flags["--anonymous-auth"]; ok {
				return false, "--anonymous-auth is not false"
			}
		}
	}
	return false, "could not determine anonymous auth setting"
}

// ---- CV3001: kubelet anonymous auth disabled ----

type cv3001Rule struct{}

func (r cv3001Rule) ID() string               { return "CV3001" }
func (r cv3001Rule) CISRef() string           { return "CIS 4.2.1" }
func (r cv3001Rule) Section() rules.CISSection { return rules.SectionWorkerNodes }
func (r cv3001Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv3001Rule) Description() string {
	return "Kubelet anonymous authentication must be disabled"
}
func (r cv3001Rule) Remediation() string {
	return "Set authentication.anonymous.enabled=false in KubeletConfiguration or --anonymous-auth=false"
}
func (r cv3001Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := findKubeletConfigObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		pass, msg := checkKubeletAnonymousAuth(obj)
		if pass {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, msg))
		}
	}
	return results
}

// ---- CV3002: kubelet authorization mode not AlwaysAllow ----

type cv3002Rule struct{}

func (r cv3002Rule) ID() string               { return "CV3002" }
func (r cv3002Rule) CISRef() string           { return "CIS 4.2.2" }
func (r cv3002Rule) Section() rules.CISSection { return rules.SectionWorkerNodes }
func (r cv3002Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv3002Rule) Description() string {
	return "Kubelet authorization mode must not be AlwaysAllow"
}
func (r cv3002Rule) Remediation() string {
	return "Set authorization.mode=Webhook in KubeletConfiguration or --authorization-mode=Webhook"
}
func (r cv3002Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := findKubeletConfigObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		if obj.Kind == "KubeletConfiguration" {
			mode, ok := getNestedString(obj.Spec, "authorization", "mode")
			if ok {
				if strings.EqualFold(mode, "AlwaysAllow") {
					results = append(results, failResult(r, obj, "authorization.mode is AlwaysAllow"))
				} else {
					results = append(results, passResult(r, obj))
				}
			} else {
				results = append(results, warnResult(r, obj, "authorization.mode not explicitly set"))
			}
		} else if obj.Kind == "Pod" {
			for _, c := range getContainers(obj.Spec) {
				flags := parseContainerFlags(c)
				if v, ok := flags["--authorization-mode"]; ok {
					if strings.EqualFold(v, "AlwaysAllow") {
						results = append(results, failResult(r, obj, "--authorization-mode is AlwaysAllow"))
					} else {
						results = append(results, passResult(r, obj))
					}
				}
			}
		}
	}
	return results
}

// ---- CV3003: kubelet protectKernelDefaults=true ----

type cv3003Rule struct{}

func (r cv3003Rule) ID() string               { return "CV3003" }
func (r cv3003Rule) CISRef() string           { return "CIS 4.2.6" }
func (r cv3003Rule) Section() rules.CISSection { return rules.SectionWorkerNodes }
func (r cv3003Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv3003Rule) Description() string {
	return "Kubelet must protect kernel defaults"
}
func (r cv3003Rule) Remediation() string {
	return "Set protectKernelDefaults=true in KubeletConfiguration or --protect-kernel-defaults=true"
}
func (r cv3003Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := findKubeletConfigObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		if obj.Kind == "KubeletConfiguration" {
			b, ok := getKubeletConfigBool(obj, "protectKernelDefaults")
			if ok && b {
				results = append(results, passResult(r, obj))
			} else {
				results = append(results, failResult(r, obj, "protectKernelDefaults is not set to true"))
			}
		} else if obj.Kind == "Pod" {
			for _, c := range getContainers(obj.Spec) {
				flags := parseContainerFlags(c)
				if flagEquals(flags, "--protect-kernel-defaults", "true") {
					results = append(results, passResult(r, obj))
				} else {
					results = append(results, failResult(r, obj, "--protect-kernel-defaults is not true"))
				}
			}
		}
	}
	return results
}

// ---- CV3004: kubelet rotateCertificates=true ----

type cv3004Rule struct{}

func (r cv3004Rule) ID() string               { return "CV3004" }
func (r cv3004Rule) CISRef() string           { return "CIS 4.2.10" }
func (r cv3004Rule) Section() rules.CISSection { return rules.SectionWorkerNodes }
func (r cv3004Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv3004Rule) Description() string       { return "Kubelet must rotate client certificates" }
func (r cv3004Rule) Remediation() string {
	return "Set rotateCertificates=true in KubeletConfiguration or --rotate-certificates=true"
}
func (r cv3004Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := findKubeletConfigObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		if obj.Kind == "KubeletConfiguration" {
			b, ok := getKubeletConfigBool(obj, "rotateCertificates")
			if ok && b {
				results = append(results, passResult(r, obj))
			} else {
				results = append(results, failResult(r, obj, "rotateCertificates is not set to true"))
			}
		} else if obj.Kind == "Pod" {
			for _, c := range getContainers(obj.Spec) {
				flags := parseContainerFlags(c)
				if flagEquals(flags, "--rotate-certificates", "true") {
					results = append(results, passResult(r, obj))
				} else {
					results = append(results, failResult(r, obj, "--rotate-certificates is not true"))
				}
			}
		}
	}
	return results
}

// ---- CV3005: kubelet clientCAFile ----

type cv3005Rule struct{}

func (r cv3005Rule) ID() string               { return "CV3005" }
func (r cv3005Rule) CISRef() string           { return "CIS 4.2.3" }
func (r cv3005Rule) Section() rules.CISSection { return rules.SectionWorkerNodes }
func (r cv3005Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv3005Rule) Description() string {
	return "Kubelet must be configured with a client CA file for authentication"
}
func (r cv3005Rule) Remediation() string {
	return "Set authentication.x509.clientCAFile in KubeletConfiguration or --client-ca-file"
}
func (r cv3005Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := findKubeletConfigObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		if obj.Kind == "KubeletConfiguration" {
			v, ok := getNestedString(obj.Spec, "authentication", "x509", "clientCAFile")
			if ok && v != "" {
				results = append(results, passResult(r, obj))
			} else {
				results = append(results, failResult(r, obj, "authentication.x509.clientCAFile is not set"))
			}
		} else if obj.Kind == "Pod" {
			for _, c := range getContainers(obj.Spec) {
				flags := parseContainerFlags(c)
				if flagIsSet(flags, "--client-ca-file") {
					results = append(results, passResult(r, obj))
				} else {
					results = append(results, failResult(r, obj, "--client-ca-file is not set"))
				}
			}
		}
	}
	return results
}

// ---- CV3006: kubelet read-only port disabled ----

type cv3006Rule struct{}

func (r cv3006Rule) ID() string               { return "CV3006" }
func (r cv3006Rule) CISRef() string           { return "CIS 4.2.4" }
func (r cv3006Rule) Section() rules.CISSection { return rules.SectionWorkerNodes }
func (r cv3006Rule) Severity() rules.Severity  { return rules.SeverityMedium }
func (r cv3006Rule) Description() string       { return "Kubelet read-only port must be disabled" }
func (r cv3006Rule) Remediation() string {
	return "Set readOnlyPort=0 in KubeletConfiguration or --read-only-port=0"
}
func (r cv3006Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	objs := findKubeletConfigObjects(ctx.Objects)
	if len(objs) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range objs {
		if obj.Kind == "KubeletConfiguration" {
			v, ok := obj.Spec["readOnlyPort"]
			if ok {
				port := fmt.Sprintf("%v", v)
				if port == "0" {
					results = append(results, passResult(r, obj))
				} else {
					results = append(results, failResult(r, obj, fmt.Sprintf("readOnlyPort is %s, must be 0", port)))
				}
			} else {
				results = append(results, warnResult(r, obj, "readOnlyPort not set; default may allow unauthenticated access"))
			}
		} else if obj.Kind == "Pod" {
			for _, c := range getContainers(obj.Spec) {
				flags := parseContainerFlags(c)
				if flagEquals(flags, "--read-only-port", "0") {
					results = append(results, passResult(r, obj))
				} else if _, ok := flags["--read-only-port"]; ok {
					results = append(results, failResult(r, obj, "--read-only-port is not 0"))
				} else {
					results = append(results, warnResult(r, obj, "--read-only-port not set"))
				}
			}
		}
	}
	return results
}

// suppress unused import warning
var _ = flagGte
