package section5

import (
	"strings"

	"github.com/ComplianceVet/compliancevet/internal/parser"
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

// ---- CV5005: Default-deny ingress NetworkPolicy per namespace ----

type cv5005Rule struct{}

func (r cv5005Rule) ID() string               { return "CV5005" }
func (r cv5005Rule) CISRef() string           { return standard + " §7.1" }
func (r cv5005Rule) Section() rules.CISSection { return rules.SectionNSACISA }
func (r cv5005Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv5005Rule) Description() string {
	return "Each namespace must have a default-deny ingress NetworkPolicy"
}
func (r cv5005Rule) Remediation() string {
	return "Create a NetworkPolicy with empty podSelector and empty ingress rules to deny all ingress traffic by default"
}
func (r cv5005Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	return checkDefaultDenyNetworkPolicy(r, ctx, "Ingress")
}

// ---- CV5006: Default-deny egress NetworkPolicy per namespace ----

type cv5006Rule struct{}

func (r cv5006Rule) ID() string               { return "CV5006" }
func (r cv5006Rule) CISRef() string           { return standard + " §7.1" }
func (r cv5006Rule) Section() rules.CISSection { return rules.SectionNSACISA }
func (r cv5006Rule) Severity() rules.Severity  { return rules.SeverityMedium }
func (r cv5006Rule) Description() string {
	return "Each namespace should have a default-deny egress NetworkPolicy"
}
func (r cv5006Rule) Remediation() string {
	return "Create a NetworkPolicy with empty podSelector, policyTypes:[Egress], and empty egress rules"
}
func (r cv5006Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	return checkDefaultDenyNetworkPolicy(r, ctx, "Egress")
}

// checkDefaultDenyNetworkPolicy checks for default-deny policies of the given type.
func checkDefaultDenyNetworkPolicy(r rules.Rule, ctx rules.RuleContext, policyType string) []rules.CheckResult {
	// Collect namespaces with workloads
	workloadNamespaces := collectWorkloadNamespaces(ctx.Objects)
	if len(workloadNamespaces) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}

	// Find namespaces with a matching default-deny policy
	covered := map[string]bool{}
	for _, obj := range ctx.Objects {
		if obj.Kind != "NetworkPolicy" {
			continue
		}
		if !isDefaultDenyPolicy(obj, policyType) {
			continue
		}
		ns := obj.Namespace
		if ns == "" {
			ns = "default"
		}
		covered[ns] = true
	}

	var results []rules.CheckResult
	for ns, nsObj := range workloadNamespaces {
		if covered[ns] {
			results = append(results, passResult(r, nsObj))
		} else {
			results = append(results, failResult(r, nsObj,
				"Namespace has no default-deny "+policyType+" NetworkPolicy"))
		}
	}
	return results
}

// isDefaultDenyPolicy returns true if the NetworkPolicy is a default-deny for the given type.
func isDefaultDenyPolicy(obj parser.K8sObject, policyType string) bool {
	// Must have empty podSelector
	podSel, _ := obj.Spec["podSelector"].(map[string]interface{})
	if podSel == nil {
		// nil podSelector means select all — that's a default policy
	} else if len(podSel) > 0 {
		// Has a non-empty podSelector — not a catch-all policy
		// Check if matchLabels/matchExpressions are empty
		ml, hasML := podSel["matchLabels"]
		me, hasME := podSel["matchExpressions"]
		if hasML || hasME {
			mlMap, _ := ml.(map[string]interface{})
			meSlice, _ := me.([]interface{})
			if len(mlMap) > 0 || len(meSlice) > 0 {
				return false
			}
		}
	}

	// Check policyTypes
	policyTypes, _ := obj.Spec["policyTypes"].([]interface{})
	hasType := false
	for _, pt := range policyTypes {
		if s, ok := pt.(string); ok && strings.EqualFold(s, policyType) {
			hasType = true
			break
		}
	}
	if !hasType && len(policyTypes) == 0 {
		// Default: NetworkPolicy without policyTypes applies to Ingress by default
		if policyType == "Ingress" {
			// Check if ingress rules are empty
			ingressRules, _ := obj.Spec["ingress"].([]interface{})
			return len(ingressRules) == 0
		}
		return false
	}
	if !hasType {
		return false
	}

	// Ingress: ingress rules must be absent or empty
	if policyType == "Ingress" {
		ingressRules, hasIngress := obj.Spec["ingress"]
		if !hasIngress {
			return true // no ingress rules = deny all ingress
		}
		il, _ := ingressRules.([]interface{})
		return len(il) == 0
	}

	// Egress: egress rules must be absent or empty
	if policyType == "Egress" {
		egressRules, hasEgress := obj.Spec["egress"]
		if !hasEgress {
			return true
		}
		el, _ := egressRules.([]interface{})
		return len(el) == 0
	}
	return false
}

func collectWorkloadNamespaces(objects []parser.K8sObject) map[string]parser.K8sObject {
	namespaces := map[string]parser.K8sObject{}
	for _, obj := range objects {
		if obj.Kind == "Namespace" {
			ns := obj.Name
			if ns == "kube-system" || ns == "kube-public" || ns == "kube-node-lease" {
				continue
			}
			namespaces[ns] = obj
		}
	}
	// Also pick up namespaces referenced by workloads
	for _, obj := range objects {
		switch obj.Kind {
		case "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
			ns := obj.Namespace
			if ns == "" {
				ns = "default"
			}
			if ns == "kube-system" || ns == "kube-public" || ns == "kube-node-lease" {
				continue
			}
			if _, exists := namespaces[ns]; !exists {
				// synthetic namespace object
				namespaces[ns] = parser.K8sObject{Kind: "Namespace", Name: ns}
			}
		}
	}
	return namespaces
}

// ---- CV5007: Ingress must have TLS configured ----

type cv5007Rule struct{}

func (r cv5007Rule) ID() string               { return "CV5007" }
func (r cv5007Rule) CISRef() string           { return standard + " §7.2" }
func (r cv5007Rule) Section() rules.CISSection { return rules.SectionNSACISA }
func (r cv5007Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv5007Rule) Description() string       { return "Ingress resources must use TLS" }
func (r cv5007Rule) Remediation() string {
	return "Configure tls section in Ingress spec with a valid TLS secret"
}
func (r cv5007Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	var ingresses []parser.K8sObject
	for _, obj := range ctx.Objects {
		if obj.Kind == "Ingress" {
			ingresses = append(ingresses, obj)
		}
	}
	if len(ingresses) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range ingresses {
		tlsRaw, hasTLS := obj.Spec["tls"]
		if !hasTLS {
			results = append(results, failResult(r, obj, "Ingress has no TLS configuration"))
			continue
		}
		tlsList, _ := tlsRaw.([]interface{})
		if len(tlsList) == 0 {
			results = append(results, failResult(r, obj, "Ingress has empty TLS configuration"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}

// ---- CV5008: LoadBalancer Service should restrict source IP ----

type cv5008Rule struct{}

func (r cv5008Rule) ID() string               { return "CV5008" }
func (r cv5008Rule) CISRef() string           { return standard + " §7.2" }
func (r cv5008Rule) Section() rules.CISSection { return rules.SectionNSACISA }
func (r cv5008Rule) Severity() rules.Severity  { return rules.SeverityMedium }
func (r cv5008Rule) Description() string {
	return "LoadBalancer Services should restrict source IP via loadBalancerSourceRanges"
}
func (r cv5008Rule) Remediation() string {
	return "Set spec.loadBalancerSourceRanges to restrict allowed source IP CIDRs"
}
func (r cv5008Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	var lbServices []parser.K8sObject
	for _, obj := range ctx.Objects {
		if obj.Kind == "Service" {
			svcType, _ := obj.Spec["type"].(string)
			if svcType == "LoadBalancer" {
				lbServices = append(lbServices, obj)
			}
		}
	}
	if len(lbServices) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	var results []rules.CheckResult
	for _, obj := range lbServices {
		ranges, hasRanges := obj.Spec["loadBalancerSourceRanges"]
		if !hasRanges {
			results = append(results, warnResult(r, obj, "LoadBalancer Service has no loadBalancerSourceRanges restriction"))
			continue
		}
		rangeList, _ := ranges.([]interface{})
		if len(rangeList) == 0 {
			results = append(results, warnResult(r, obj, "LoadBalancer Service has empty loadBalancerSourceRanges"))
		} else {
			results = append(results, passResult(r, obj))
		}
	}
	return results
}
