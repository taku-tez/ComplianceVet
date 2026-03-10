package parser_test

import (
	"strings"
	"testing"

	"github.com/ComplianceVet/compliancevet/internal/parser"
)

func TestParseYAML_SingleDoc(t *testing.T) {
	yaml := `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
spec:
  containers:
  - name: app
    image: nginx
`
	res, err := parser.ParseYAML(strings.NewReader(yaml), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(res.Objects))
	}
	obj := res.Objects[0]
	if obj.Kind != "Pod" {
		t.Errorf("expected Kind=Pod, got %s", obj.Kind)
	}
	if obj.Name != "test-pod" {
		t.Errorf("expected Name=test-pod, got %s", obj.Name)
	}
	if obj.Namespace != "default" {
		t.Errorf("expected Namespace=default, got %s", obj.Namespace)
	}
}

func TestParseYAML_MultiDoc(t *testing.T) {
	yaml := `
apiVersion: v1
kind: Pod
metadata:
  name: pod1
spec: {}
---
apiVersion: v1
kind: Service
metadata:
  name: svc1
spec: {}
`
	res, err := parser.ParseYAML(strings.NewReader(yaml), "multi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Objects) != 2 {
		t.Fatalf("expected 2 objects, got %d", len(res.Objects))
	}
}

func TestParseYAML_SkipsNonK8s(t *testing.T) {
	yaml := `
foo: bar
baz: 123
`
	res, err := parser.ParseYAML(strings.NewReader(yaml), "nonk8s.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Objects) != 0 {
		t.Errorf("expected 0 objects for non-k8s YAML, got %d", len(res.Objects))
	}
}
