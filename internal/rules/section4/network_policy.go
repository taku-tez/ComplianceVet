package section4

import (
	"github.com/ComplianceVet/compliancevet/internal/parser"
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

// ---- CV4010: Every Namespace must have at least one NetworkPolicy ----

type cv4010Rule struct{}

func (r cv4010Rule) ID() string               { return "CV4010" }
func (r cv4010Rule) CISRef() string           { return "CIS 5.3.2" }
func (r cv4010Rule) Section() rules.CISSection { return rules.SectionPolicies }
func (r cv4010Rule) Severity() rules.Severity  { return rules.SeverityHigh }
func (r cv4010Rule) Description() string {
	return "Every Namespace must have at least one NetworkPolicy"
}
func (r cv4010Rule) Remediation() string {
	return "Create a default-deny NetworkPolicy in each Namespace"
}
func (r cv4010Rule) Check(ctx rules.RuleContext) []rules.CheckResult {
	// Collect all namespaces
	namespaceNames := map[string]parser.K8sObject{}
	for _, obj := range ctx.Objects {
		if obj.Kind == "Namespace" {
			namespaceNames[obj.Name] = obj
		}
	}

	// Collect namespaces referenced by workloads
	workloadNamespaces := map[string]bool{}
	for _, obj := range ctx.Objects {
		switch obj.Kind {
		case "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
			ns := obj.Namespace
			if ns == "" {
				ns = "default"
			}
			if ns != "kube-system" && ns != "kube-public" && ns != "kube-node-lease" {
				workloadNamespaces[ns] = true
			}
		}
	}

	// Collect namespaces that have NetworkPolicies
	coveredNamespaces := map[string]bool{}
	for _, obj := range ctx.Objects {
		if obj.Kind == "NetworkPolicy" {
			ns := obj.Namespace
			if ns == "" {
				ns = "default"
			}
			coveredNamespaces[ns] = true
		}
	}

	if len(workloadNamespaces) == 0 && len(namespaceNames) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}

	var results []rules.CheckResult

	// Check explicit Namespace objects
	for ns, nsObj := range namespaceNames {
		if ns == "kube-system" || ns == "kube-public" || ns == "kube-node-lease" {
			continue
		}
		if coveredNamespaces[ns] {
			results = append(results, passResult(r, nsObj))
		} else {
			results = append(results, failResult(r, nsObj, "Namespace has no NetworkPolicy"))
		}
	}

	// Check namespaces from workloads that may not have a Namespace object
	for ns := range workloadNamespaces {
		if _, alreadyChecked := namespaceNames[ns]; alreadyChecked {
			continue
		}
		// Create a synthetic object for reporting
		synthetic := parser.K8sObject{
			Kind:      "Namespace",
			Name:      ns,
			Namespace: "",
		}
		if coveredNamespaces[ns] {
			results = append(results, passResult(r, synthetic))
		} else {
			results = append(results, failResult(r, synthetic, "Namespace has no NetworkPolicy"))
		}
	}

	if len(results) == 0 {
		return []rules.CheckResult{notApplicable(r)}
	}
	return results
}
