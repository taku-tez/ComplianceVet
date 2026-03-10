package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/ComplianceVet/compliancevet/internal/checker"
	"github.com/ComplianceVet/compliancevet/internal/cluster"
	"github.com/ComplianceVet/compliancevet/internal/report"
	"github.com/ComplianceVet/compliancevet/internal/rules"

	_ "github.com/ComplianceVet/compliancevet/internal/rules/section1"
	_ "github.com/ComplianceVet/compliancevet/internal/rules/section2"
	_ "github.com/ComplianceVet/compliancevet/internal/rules/section3"
	_ "github.com/ComplianceVet/compliancevet/internal/rules/section4"
	_ "github.com/ComplianceVet/compliancevet/internal/rules/section5"
	_ "github.com/ComplianceVet/compliancevet/internal/rules/section6"
)

var (
	clusterFlagContext       string
	clusterFlagKubeConfig    string
	clusterFlagNamespace     string
	clusterFlagAllNamespaces bool
	clusterFlagBenchmark     string
	clusterFlagOutput        string
	clusterFlagVerbose       bool
	clusterFlagNoColor       bool
	clusterFlagMinSeverity   string
	clusterFlagIgnore        []string
	clusterFlagFailOnScore   int
	clusterFlagTimeout       int
)

var clusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Scan a live Kubernetes cluster for compliance",
	Long: `Connect to a live Kubernetes cluster via kubeconfig and evaluate
all resources against compliance standards (CIS, NSA/CISA, PCI-DSS).`,
	RunE: runClusterScan,
}

func init() {
	clusterCmd.Flags().StringVar(&clusterFlagContext, "context", "", "kubectl context name (default: current context)")
	clusterCmd.Flags().StringVar(&clusterFlagKubeConfig, "kubeconfig", "", "Path to kubeconfig (default: ~/.kube/config)")
	clusterCmd.Flags().StringVarP(&clusterFlagNamespace, "namespace", "n", "", "Namespace to scan (default: all namespaces)")
	clusterCmd.Flags().BoolVar(&clusterFlagAllNamespaces, "all-namespaces", true, "Scan all namespaces")
	clusterCmd.Flags().StringVar(&clusterFlagBenchmark, "benchmark", "all", "Benchmark: all|cis|nsa|pci-dss")
	clusterCmd.Flags().StringVarP(&clusterFlagOutput, "output", "o", "text", "Output format: text|table|json")
	clusterCmd.Flags().BoolVarP(&clusterFlagVerbose, "verbose", "v", false, "Show PASS and NOT_APPLICABLE results")
	clusterCmd.Flags().BoolVar(&clusterFlagNoColor, "no-color", false, "Disable color output")
	clusterCmd.Flags().StringVar(&clusterFlagMinSeverity, "min-severity", "", "Minimum severity: CRITICAL|HIGH|MEDIUM|LOW")
	clusterCmd.Flags().StringSliceVar(&clusterFlagIgnore, "ignore", nil, "Rule IDs to skip")
	clusterCmd.Flags().IntVar(&clusterFlagFailOnScore, "fail-on-score", 0, "Exit non-zero if score below N")
	clusterCmd.Flags().IntVar(&clusterFlagTimeout, "timeout", 60, "API request timeout in seconds")
}

func runClusterScan(cmd *cobra.Command, args []string) error {
	if clusterFlagNoColor {
		color.NoColor = true
	}

	fmt.Fprintln(os.Stderr, "Connecting to cluster...")

	client, err := cluster.New(cluster.Options{
		KubeContext:   clusterFlagContext,
		KubeConfig:    clusterFlagKubeConfig,
		Namespace:     clusterFlagNamespace,
		AllNamespaces: clusterFlagAllNamespaces || clusterFlagNamespace == "",
	})
	if err != nil {
		return fmt.Errorf("connect to cluster: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(clusterFlagTimeout)*time.Second)
	defer cancel()

	fmt.Fprintln(os.Stderr, "Fetching resources...")
	objects, err := client.FetchObjects(ctx)
	if err != nil {
		return fmt.Errorf("fetch cluster resources: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Fetched %d resources\n", len(objects))

	// Determine sections from benchmark flag
	var sections []rules.CISSection
	bm := strings.ToLower(strings.TrimSpace(clusterFlagBenchmark))
	if bm != "" && bm != "all" {
		if secs, ok := benchmarkSections[bm]; ok {
			sections = secs
		} else {
			return fmt.Errorf("unknown benchmark %q; valid: all, cis, nsa, pci-dss", clusterFlagBenchmark)
		}
	}

	cfg := checker.Config{
		IgnoreRules: clusterFlagIgnore,
		Sections:    sections,
		MinSeverity: rules.Severity(strings.ToUpper(clusterFlagMinSeverity)),
	}

	results := checker.Run(objects, cfg)
	rep := report.New(results, []string{"<live cluster>"})

	switch strings.ToLower(clusterFlagOutput) {
	case "json":
		if err := report.WriteJSON(os.Stdout, rep); err != nil {
			return err
		}
	case "table":
		report.WriteTable(os.Stdout, rep, clusterFlagVerbose)
	default:
		report.WriteText(os.Stdout, rep, clusterFlagVerbose)
	}

	failCount := rep.FailCount()
	if clusterFlagFailOnScore > 0 && int(rep.Score.Score) < clusterFlagFailOnScore {
		os.Exit(1)
	}
	if failCount > 0 {
		os.Exit(1)
	}
	return nil
}
