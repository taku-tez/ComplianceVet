// Package cluster provides live Kubernetes cluster scanning via the API server.
package cluster

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/ComplianceVet/compliancevet/internal/parser"
)

// Options configures a live cluster scan.
type Options struct {
	KubeContext   string // kubectl context name (empty = current context)
	KubeConfig    string // path to kubeconfig (empty = default)
	Namespace     string // empty = all namespaces
	AllNamespaces bool
}

// Client wraps a Kubernetes client and converts live resources to K8sObjects.
type Client struct {
	cs   kubernetes.Interface
	opts Options
}

// New creates a new cluster Client.
func New(opts Options) (*Client, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if opts.KubeConfig != "" {
		loadingRules.ExplicitPath = opts.KubeConfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if opts.KubeContext != "" {
		overrides.CurrentContext = opts.KubeContext
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, overrides,
	).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create k8s client: %w", err)
	}
	return &Client{cs: cs, opts: opts}, nil
}

// FetchObjects retrieves all relevant objects from the live cluster.
func (c *Client) FetchObjects(ctx context.Context) ([]parser.K8sObject, error) {
	ns := c.opts.Namespace
	if c.opts.AllNamespaces {
		ns = ""
	}

	var objects []parser.K8sObject

	// Pods (including static pods for control plane)
	pods, err := c.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	for _, pod := range pods.Items {
		objects = append(objects, podToK8sObject(pod))
	}

	// Namespaces
	nsList, err := c.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	for _, ns := range nsList.Items {
		objects = append(objects, namespaceToK8sObject(ns))
	}

	// NetworkPolicies
	netpols, err := c.cs.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list networkpolicies: %w", err)
	}
	for _, np := range netpols.Items {
		objects = append(objects, networkPolicyToK8sObject(np))
	}

	// ClusterRoles
	crs, err := c.cs.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterroles: %w", err)
	}
	for _, cr := range crs.Items {
		objects = append(objects, clusterRoleToK8sObject(cr))
	}

	// ClusterRoleBindings
	crbs, err := c.cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterrolebindings: %w", err)
	}
	for _, crb := range crbs.Items {
		objects = append(objects, clusterRoleBindingToK8sObject(crb))
	}

	// Roles
	roles, err := c.cs.RbacV1().Roles(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	for _, r := range roles.Items {
		objects = append(objects, roleToK8sObject(r))
	}

	// RoleBindings
	rbs, err := c.cs.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list rolebindings: %w", err)
	}
	for _, rb := range rbs.Items {
		objects = append(objects, roleBindingToK8sObject(rb))
	}

	// ServiceAccounts
	sas, err := c.cs.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list serviceaccounts: %w", err)
	}
	for _, sa := range sas.Items {
		objects = append(objects, serviceAccountToK8sObject(sa))
	}

	// ConfigMaps (for kubelet config)
	cms, err := c.cs.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list configmaps: %w", err)
	}
	for _, cm := range cms.Items {
		objects = append(objects, configMapToK8sObject(cm))
	}

	// Services (for LoadBalancer checks)
	svcs, err := c.cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	for _, svc := range svcs.Items {
		objects = append(objects, serviceToK8sObject(svc))
	}

	return objects, nil
}

func podToK8sObject(pod corev1.Pod) parser.K8sObject {
	spec := podSpecToMap(pod.Spec)
	return parser.K8sObject{
		APIVersion:  "v1",
		Kind:        "Pod",
		Name:        pod.Name,
		Namespace:   pod.Namespace,
		Labels:      pod.Labels,
		Annotations: pod.Annotations,
		Spec:        spec,
		Raw:         map[string]interface{}{"kind": "Pod", "spec": spec},
		SourceFile:  "<cluster>",
	}
}

func podSpecToMap(spec corev1.PodSpec) map[string]interface{} {
	containers := make([]interface{}, 0, len(spec.Containers))
	for _, c := range spec.Containers {
		containers = append(containers, containerToMap(c))
	}
	initContainers := make([]interface{}, 0, len(spec.InitContainers))
	for _, c := range spec.InitContainers {
		initContainers = append(initContainers, containerToMap(c))
	}
	m := map[string]interface{}{
		"containers":     containers,
		"initContainers": initContainers,
	}
	if spec.HostPID {
		m["hostPID"] = true
	}
	if spec.HostIPC {
		m["hostIPC"] = true
	}
	if spec.HostNetwork {
		m["hostNetwork"] = true
	}
	if spec.ServiceAccountName != "" {
		m["serviceAccountName"] = spec.ServiceAccountName
	}
	if spec.AutomountServiceAccountToken != nil {
		m["automountServiceAccountToken"] = *spec.AutomountServiceAccountToken
	}
	if spec.SecurityContext != nil {
		psc := map[string]interface{}{}
		if spec.SecurityContext.RunAsNonRoot != nil {
			psc["runAsNonRoot"] = *spec.SecurityContext.RunAsNonRoot
		}
		if spec.SecurityContext.RunAsUser != nil {
			psc["runAsUser"] = *spec.SecurityContext.RunAsUser
		}
		if spec.SecurityContext.SeccompProfile != nil {
			psc["seccompProfile"] = map[string]interface{}{
				"type": string(spec.SecurityContext.SeccompProfile.Type),
			}
		}
		m["securityContext"] = psc
	}
	return m
}

func containerToMap(c corev1.Container) map[string]interface{} {
	args := make([]interface{}, len(c.Args))
	for i, a := range c.Args {
		args[i] = a
	}
	cmd := make([]interface{}, len(c.Command))
	for i, a := range c.Command {
		cmd[i] = a
	}
	cm := map[string]interface{}{
		"name":    c.Name,
		"image":   c.Image,
		"command": cmd,
		"args":    args,
	}
	if c.SecurityContext != nil {
		sc := map[string]interface{}{}
		if c.SecurityContext.Privileged != nil {
			sc["privileged"] = *c.SecurityContext.Privileged
		}
		if c.SecurityContext.RunAsNonRoot != nil {
			sc["runAsNonRoot"] = *c.SecurityContext.RunAsNonRoot
		}
		if c.SecurityContext.RunAsUser != nil {
			sc["runAsUser"] = *c.SecurityContext.RunAsUser
		}
		if c.SecurityContext.ReadOnlyRootFilesystem != nil {
			sc["readOnlyRootFilesystem"] = *c.SecurityContext.ReadOnlyRootFilesystem
		}
		if c.SecurityContext.Capabilities != nil {
			caps := map[string]interface{}{}
			drop := make([]interface{}, len(c.SecurityContext.Capabilities.Drop))
			for i, d := range c.SecurityContext.Capabilities.Drop {
				drop[i] = string(d)
			}
			caps["drop"] = drop
			add := make([]interface{}, len(c.SecurityContext.Capabilities.Add))
			for i, a := range c.SecurityContext.Capabilities.Add {
				add[i] = string(a)
			}
			caps["add"] = add
			sc["capabilities"] = caps
		}
		cm["securityContext"] = sc
	}
	return cm
}

func namespaceToK8sObject(ns corev1.Namespace) parser.K8sObject {
	return parser.K8sObject{
		APIVersion:  "v1",
		Kind:        "Namespace",
		Name:        ns.Name,
		Labels:      ns.Labels,
		Annotations: ns.Annotations,
		Spec:        map[string]interface{}{},
		Raw:         map[string]interface{}{"kind": "Namespace"},
		SourceFile:  "<cluster>",
	}
}

func networkPolicyToK8sObject(np networkingv1.NetworkPolicy) parser.K8sObject {
	policyTypes := make([]interface{}, len(np.Spec.PolicyTypes))
	for i, pt := range np.Spec.PolicyTypes {
		policyTypes[i] = string(pt)
	}
	ingress := make([]interface{}, len(np.Spec.Ingress))
	egress := make([]interface{}, len(np.Spec.Egress))
	spec := map[string]interface{}{
		"podSelector": map[string]interface{}{},
		"policyTypes": policyTypes,
		"ingress":     ingress,
		"egress":      egress,
	}
	return parser.K8sObject{
		APIVersion: "networking.k8s.io/v1",
		Kind:       "NetworkPolicy",
		Name:       np.Name,
		Namespace:  np.Namespace,
		Spec:       spec,
		Raw:        map[string]interface{}{"kind": "NetworkPolicy", "spec": spec},
		SourceFile: "<cluster>",
	}
}

func clusterRoleToK8sObject(cr rbacv1.ClusterRole) parser.K8sObject {
	rulesRaw := make([]interface{}, len(cr.Rules))
	for i, r := range cr.Rules {
		verbs := make([]interface{}, len(r.Verbs))
		for j, v := range r.Verbs {
			verbs[j] = v
		}
		resources := make([]interface{}, len(r.Resources))
		for j, res := range r.Resources {
			resources[j] = res
		}
		rulesRaw[i] = map[string]interface{}{
			"verbs":     verbs,
			"resources": resources,
		}
	}
	raw := map[string]interface{}{
		"kind":     "ClusterRole",
		"metadata": map[string]interface{}{"name": cr.Name},
		"rules":    rulesRaw,
	}
	return parser.K8sObject{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       "ClusterRole",
		Name:       cr.Name,
		Spec:       map[string]interface{}{},
		Raw:        raw,
		SourceFile: "<cluster>",
	}
}

func clusterRoleBindingToK8sObject(crb rbacv1.ClusterRoleBinding) parser.K8sObject {
	subjects := make([]interface{}, len(crb.Subjects))
	for i, s := range crb.Subjects {
		subjects[i] = map[string]interface{}{
			"kind":      s.Kind,
			"name":      s.Name,
			"namespace": s.Namespace,
		}
	}
	raw := map[string]interface{}{
		"kind":     "ClusterRoleBinding",
		"metadata": map[string]interface{}{"name": crb.Name},
		"roleRef": map[string]interface{}{
			"kind": crb.RoleRef.Kind,
			"name": crb.RoleRef.Name,
		},
		"subjects": subjects,
	}
	return parser.K8sObject{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       "ClusterRoleBinding",
		Name:       crb.Name,
		Spec:       map[string]interface{}{},
		Raw:        raw,
		SourceFile: "<cluster>",
	}
}

func roleToK8sObject(r rbacv1.Role) parser.K8sObject {
	rulesRaw := make([]interface{}, len(r.Rules))
	for i, rule := range r.Rules {
		verbs := make([]interface{}, len(rule.Verbs))
		for j, v := range rule.Verbs {
			verbs[j] = v
		}
		resources := make([]interface{}, len(rule.Resources))
		for j, res := range rule.Resources {
			resources[j] = res
		}
		rulesRaw[i] = map[string]interface{}{
			"verbs":     verbs,
			"resources": resources,
		}
	}
	raw := map[string]interface{}{
		"kind":     "Role",
		"metadata": map[string]interface{}{"name": r.Name, "namespace": r.Namespace},
		"rules":    rulesRaw,
	}
	return parser.K8sObject{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       "Role",
		Name:       r.Name,
		Namespace:  r.Namespace,
		Spec:       map[string]interface{}{},
		Raw:        raw,
		SourceFile: "<cluster>",
	}
}

func roleBindingToK8sObject(rb rbacv1.RoleBinding) parser.K8sObject {
	subjects := make([]interface{}, len(rb.Subjects))
	for i, s := range rb.Subjects {
		subjects[i] = map[string]interface{}{
			"kind":      s.Kind,
			"name":      s.Name,
			"namespace": s.Namespace,
		}
	}
	raw := map[string]interface{}{
		"kind":     "RoleBinding",
		"metadata": map[string]interface{}{"name": rb.Name, "namespace": rb.Namespace},
		"roleRef": map[string]interface{}{
			"kind": rb.RoleRef.Kind,
			"name": rb.RoleRef.Name,
		},
		"subjects": subjects,
	}
	return parser.K8sObject{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       "RoleBinding",
		Name:       rb.Name,
		Namespace:  rb.Namespace,
		Spec:       map[string]interface{}{},
		Raw:        raw,
		SourceFile: "<cluster>",
	}
}

func serviceAccountToK8sObject(sa corev1.ServiceAccount) parser.K8sObject {
	raw := map[string]interface{}{
		"kind":     "ServiceAccount",
		"metadata": map[string]interface{}{"name": sa.Name, "namespace": sa.Namespace},
	}
	if sa.AutomountServiceAccountToken != nil {
		raw["automountServiceAccountToken"] = *sa.AutomountServiceAccountToken
	}
	return parser.K8sObject{
		APIVersion: "v1",
		Kind:       "ServiceAccount",
		Name:       sa.Name,
		Namespace:  sa.Namespace,
		Spec:       map[string]interface{}{},
		Raw:        raw,
		SourceFile: "<cluster>",
	}
}

func configMapToK8sObject(cm corev1.ConfigMap) parser.K8sObject {
	data := map[string]interface{}{}
	for k, v := range cm.Data {
		data[k] = v
	}
	return parser.K8sObject{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Name:       cm.Name,
		Namespace:  cm.Namespace,
		Spec:       data,
		Raw:        map[string]interface{}{"kind": "ConfigMap", "data": data},
		SourceFile: "<cluster>",
	}
}

func serviceToK8sObject(svc corev1.Service) parser.K8sObject {
	spec := map[string]interface{}{
		"type": string(svc.Spec.Type),
	}
	if len(svc.Spec.LoadBalancerSourceRanges) > 0 {
		ranges := make([]interface{}, len(svc.Spec.LoadBalancerSourceRanges))
		for i, r := range svc.Spec.LoadBalancerSourceRanges {
			ranges[i] = r
		}
		spec["loadBalancerSourceRanges"] = ranges
	}
	return parser.K8sObject{
		APIVersion: "v1",
		Kind:       "Service",
		Name:       svc.Name,
		Namespace:  svc.Namespace,
		Spec:       spec,
		Raw:        map[string]interface{}{"kind": "Service", "spec": spec},
		SourceFile: "<cluster>",
	}
}
