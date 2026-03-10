package checker_test

import (
	"testing"

	"github.com/ComplianceVet/compliancevet/internal/checker"
	"github.com/ComplianceVet/compliancevet/internal/parser"
	"github.com/ComplianceVet/compliancevet/internal/rules"

	_ "github.com/ComplianceVet/compliancevet/internal/rules/section1"
	_ "github.com/ComplianceVet/compliancevet/internal/rules/section4"
)

func TestRun_APIServerPass(t *testing.T) {
	objects := []parser.K8sObject{
		{
			Kind:      "Pod",
			Name:      "kube-apiserver",
			Namespace: "kube-system",
			Spec: map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name":  "kube-apiserver",
						"image": "registry.k8s.io/kube-apiserver:v1.28.0",
						"command": []interface{}{
							"kube-apiserver",
							"--anonymous-auth=false",
							"--audit-log-path=/var/log/audit.log",
							"--audit-log-maxage=30",
							"--audit-log-maxbackup=10",
							"--audit-log-maxsize=100",
							"--authorization-mode=Node,RBAC",
							"--enable-admission-plugins=NodeRestriction,PodSecurity",
							"--tls-cert-file=/etc/certs/apiserver.crt",
							"--tls-private-key-file=/etc/certs/apiserver.key",
						},
					},
				},
			},
		},
	}

	cfg := checker.Config{
		Sections: []rules.CISSection{rules.SectionControlPlane},
	}
	results := checker.Run(objects, cfg)

	failCount := 0
	for _, r := range results {
		if r.Status == rules.StatusFail {
			failCount++
			t.Logf("FAIL: %s - %s", r.RuleID, r.Message)
		}
	}
	if failCount > 0 {
		t.Errorf("expected 0 failures, got %d", failCount)
	}
}

func TestRun_APIServerFail_AnonymousAuth(t *testing.T) {
	objects := []parser.K8sObject{
		{
			Kind:      "Pod",
			Name:      "kube-apiserver",
			Namespace: "kube-system",
			Spec: map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name":  "kube-apiserver",
						"image": "registry.k8s.io/kube-apiserver:v1.28.0",
						"command": []interface{}{
							"kube-apiserver",
							"--anonymous-auth=true",
						},
					},
				},
			},
		},
	}

	cfg := checker.Config{
		Sections: []rules.CISSection{rules.SectionControlPlane},
	}
	results := checker.Run(objects, cfg)

	found := false
	for _, r := range results {
		if r.RuleID == "CV1001" && r.Status == rules.StatusFail {
			found = true
		}
	}
	if !found {
		t.Error("expected CV1001 FAIL for --anonymous-auth=true")
	}
}

func TestRun_PrivilegedContainer(t *testing.T) {
	objects := []parser.K8sObject{
		{
			Kind:      "Pod",
			Name:      "bad-pod",
			Namespace: "default",
			Spec: map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name":  "app",
						"image": "nginx",
						"securityContext": map[string]interface{}{
							"privileged": true,
						},
					},
				},
			},
		},
	}

	cfg := checker.Config{
		Sections: []rules.CISSection{rules.SectionPolicies},
	}
	results := checker.Run(objects, cfg)

	found := false
	for _, r := range results {
		if r.RuleID == "CV4006" && r.Status == rules.StatusFail {
			found = true
		}
	}
	if !found {
		t.Error("expected CV4006 FAIL for privileged container")
	}
}

func TestRun_WildcardVerb(t *testing.T) {
	objects := []parser.K8sObject{
		{
			Kind: "ClusterRole",
			Name: "bad-role",
			Raw: map[string]interface{}{
				"kind":       "ClusterRole",
				"apiVersion": "rbac.authorization.k8s.io/v1",
				"metadata":   map[string]interface{}{"name": "bad-role"},
				"rules": []interface{}{
					map[string]interface{}{
						"apiGroups": []interface{}{"*"},
						"resources": []interface{}{"pods"},
						"verbs":     []interface{}{"*"},
					},
				},
			},
		},
	}

	cfg := checker.Config{
		Sections: []rules.CISSection{rules.SectionPolicies},
	}
	results := checker.Run(objects, cfg)

	found := false
	for _, r := range results {
		if r.RuleID == "CV4001" && r.Status == rules.StatusFail {
			found = true
		}
	}
	if !found {
		t.Error("expected CV4001 FAIL for wildcard verb")
	}
}
