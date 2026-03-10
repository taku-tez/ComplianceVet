package section2

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ComplianceVet/compliancevet/internal/parser"
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

func findEtcdObjects(objects []parser.K8sObject) []parser.K8sObject {
	var result []parser.K8sObject
	for _, obj := range objects {
		if obj.Kind != "Pod" {
			continue
		}
		if strings.Contains(strings.ToLower(obj.Name), "etcd") {
			result = append(result, obj)
			continue
		}
		for _, c := range getContainers(obj.Spec) {
			image, _ := c["image"].(string)
			if strings.Contains(strings.ToLower(image), "etcd") {
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

func getEtcdFlags(obj parser.K8sObject) (map[string]string, bool) {
	for _, c := range getContainers(obj.Spec) {
		name, _ := c["name"].(string)
		image, _ := c["image"].(string)
		if strings.Contains(strings.ToLower(name), "etcd") ||
			strings.Contains(strings.ToLower(image), "etcd") {
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

func flagIsSet(flags map[string]string, name string) bool {
	v, ok := flags[name]
	return ok && v != ""
}

func flagEquals(flags map[string]string, name, expected string) bool {
	v, ok := flags[name]
	return ok && strings.EqualFold(v, expected)
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

func resourceRef(obj parser.K8sObject) string {
	if obj.Namespace != "" {
		return fmt.Sprintf("%s/%s/%s", obj.Kind, obj.Namespace, obj.Name)
	}
	return fmt.Sprintf("%s/%s", obj.Kind, obj.Name)
}

// ---- CV2001: etcd TLS cert and key ----

type cv2001Rule struct{}

func (r cv2001Rule) ID() string               { return "CV2001" }
func (r cv2001Rule) CISRef() string           { return "CIS 2.1" }
func (r cv2001Rule) Section() rules.CISSection { return rules.SectionEtcd }
func (r cv2001Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv2001Rule) Description() string       { return "etcd must be configured with TLS client certificate and key" }
func (r cv2001Rule) Remediation() string {
	return "Set --cert-file and --key-file in etcd arguments"
}
func (r cv2001Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findEtcdObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getEtcdFlags(obj)
		if !ok {
			continue
		}
		if flagIsSet(flags, "--cert-file") && flagIsSet(flags, "--key-file") {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "--cert-file and/or --key-file are not set"))
		}
	}
	return results
}

// ---- CV2002: etcd --client-cert-auth=true ----

type cv2002Rule struct{}

func (r cv2002Rule) ID() string               { return "CV2002" }
func (r cv2002Rule) CISRef() string           { return "CIS 2.2" }
func (r cv2002Rule) Section() rules.CISSection { return rules.SectionEtcd }
func (r cv2002Rule) Severity() rules.Severity  { return rules.SeverityCritical }
func (r cv2002Rule) Description() string       { return "etcd client certificate authentication must be enabled" }
func (r cv2002Rule) Remediation() string {
	return "Set --client-cert-auth=true in etcd arguments"
}
func (r cv2002Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findEtcdObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getEtcdFlags(obj)
		if !ok {
			continue
		}
		if flagEquals(flags, "--client-cert-auth", "true") {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "--client-cert-auth is not set to true"))
		}
	}
	return results
}

// ---- CV2003: etcd --auto-tls must not be true ----

type cv2003Rule struct{}

func (r cv2003Rule) ID() string               { return "CV2003" }
func (r cv2003Rule) CISRef() string           { return "CIS 2.3" }
func (r cv2003Rule) Section() rules.CISSection { return rules.SectionEtcd }
func (r cv2003Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv2003Rule) Description() string       { return "etcd must not use self-signed auto-TLS certificates" }
func (r cv2003Rule) Remediation() string {
	return "Remove --auto-tls=true from etcd arguments and configure proper TLS certificates"
}
func (r cv2003Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findEtcdObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getEtcdFlags(obj)
		if !ok {
			continue
		}
		if flagEquals(flags, "--auto-tls", "true") {
			results = append(results, failResult(r, obj, "--auto-tls is set to true; use proper TLS certificates"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

// ---- CV2004: etcd peer TLS cert and key ----

type cv2004Rule struct{}

func (r cv2004Rule) ID() string               { return "CV2004" }
func (r cv2004Rule) CISRef() string           { return "CIS 2.4" }
func (r cv2004Rule) Section() rules.CISSection { return rules.SectionEtcd }
func (r cv2004Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv2004Rule) Description() string       { return "etcd peer communication must be configured with TLS" }
func (r cv2004Rule) Remediation() string {
	return "Set --peer-cert-file and --peer-key-file in etcd arguments"
}
func (r cv2004Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findEtcdObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getEtcdFlags(obj)
		if !ok {
			continue
		}
		if flagIsSet(flags, "--peer-cert-file") && flagIsSet(flags, "--peer-key-file") {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "--peer-cert-file and/or --peer-key-file are not set"))
		}
	}
	return results
}

// ---- CV2005: etcd --peer-client-cert-auth=true ----

type cv2005Rule struct{}

func (r cv2005Rule) ID() string               { return "CV2005" }
func (r cv2005Rule) CISRef() string           { return "CIS 2.5" }
func (r cv2005Rule) Section() rules.CISSection { return rules.SectionEtcd }
func (r cv2005Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv2005Rule) Description() string {
	return "etcd peer client certificate authentication must be enabled"
}
func (r cv2005Rule) Remediation() string {
	return "Set --peer-client-cert-auth=true in etcd arguments"
}
func (r cv2005Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findEtcdObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getEtcdFlags(obj)
		if !ok {
			continue
		}
		if flagEquals(flags, "--peer-client-cert-auth", "true") {
			results = append(results, passResult(r, obj))
		} else {
			results = append(results, failResult(r, obj, "--peer-client-cert-auth is not set to true"))
		}
	}
	return results
}

// ---- CV2006: etcd --peer-auto-tls must not be true ----

type cv2006Rule struct{}

func (r cv2006Rule) ID() string               { return "CV2006" }
func (r cv2006Rule) CISRef() string           { return "CIS 2.6" }
func (r cv2006Rule) Section() rules.CISSection { return rules.SectionEtcd }
func (r cv2006Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv2006Rule) Description() string {
	return "etcd must not use self-signed auto-TLS for peer communication"
}
func (r cv2006Rule) Remediation() string {
	return "Remove --peer-auto-tls=true from etcd arguments"
}
func (r cv2006Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	pods := findEtcdObjects(ctx.Objects)
	if len(pods) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range pods {
		flags, ok := getEtcdFlags(obj)
		if !ok {
			continue
		}
		if flagEquals(flags, "--peer-auto-tls", "true") {
			results = append(results, failResult(r, obj, "--peer-auto-tls is set to true"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

// suppress unused import warning
var _ = flagGte
