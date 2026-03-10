package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/ComplianceVet/compliancevet/internal/checker"
	"github.com/ComplianceVet/compliancevet/internal/report"
	"github.com/ComplianceVet/compliancevet/internal/rules"
	"github.com/ComplianceVet/compliancevet/internal/scanner"

	// Register all rules via init()
	_ "github.com/ComplianceVet/compliancevet/internal/rules/section1"
	_ "github.com/ComplianceVet/compliancevet/internal/rules/section2"
	_ "github.com/ComplianceVet/compliancevet/internal/rules/section3"
	_ "github.com/ComplianceVet/compliancevet/internal/rules/section4"
	_ "github.com/ComplianceVet/compliancevet/internal/rules/section5"
	_ "github.com/ComplianceVet/compliancevet/internal/rules/section6"
)

var (
	flagOutput      string
	flagBenchmark   string
	flagSections    []string
	flagIgnore      []string
	flagMinSeverity string
	flagNoColor     bool
	flagFailOnScore int
	flagRecursive   bool
	flagVerbose     bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [flags] <path...>",
	Short: "Scan Kubernetes manifests for compliance",
	Long: `Scan one or more directories or files containing Kubernetes manifests
and evaluate them against compliance standards:
  - CIS Kubernetes Benchmark v1.9
  - NSA/CISA Kubernetes Hardening Guide v1.2
  - PCI-DSS v4.0`,
	Args: cobra.MinimumNArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&flagOutput, "output", "o", "text", "Output format: text|table|json|html")
	scanCmd.Flags().StringVar(&flagBenchmark, "benchmark", "all", "Benchmark to run: all|cis|nsa|pci-dss")
	scanCmd.Flags().StringSliceVarP(&flagSections, "section", "s", nil, "Sections to check: 1,2,3,4,5,6 (default all)")
	scanCmd.Flags().StringSliceVar(&flagIgnore, "ignore", nil, "Rule IDs to skip (e.g. CV1001,CV2001)")
	scanCmd.Flags().StringVar(&flagMinSeverity, "min-severity", "", "Minimum severity: CRITICAL|HIGH|MEDIUM|LOW")
	scanCmd.Flags().BoolVar(&flagNoColor, "no-color", false, "Disable color output")
	scanCmd.Flags().IntVar(&flagFailOnScore, "fail-on-score", 0, "Exit non-zero if overall score below N")
	scanCmd.Flags().BoolVarP(&flagRecursive, "recursive", "r", true, "Recursively scan directories")
	scanCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Show PASS and NOT_APPLICABLE results")
}

// benchmarkSections maps benchmark names to their CIS sections.
var benchmarkSections = map[string][]rules.CISSection{
	"cis": {
		rules.SectionControlPlane,
		rules.SectionEtcd,
		rules.SectionWorkerNodes,
		rules.SectionPolicies,
	},
	"nsa":     {rules.SectionNSACISA},
	"nsa-cisa": {rules.SectionNSACISA},
	"pci-dss": {rules.SectionPCIDSS},
	"pci":     {rules.SectionPCIDSS},
}

func runScan(cmd *cobra.Command, args []string) error {
	if flagNoColor {
		color.NoColor = true
	}

	// Determine which sections to run
	var sections []rules.CISSection

	// --benchmark flag takes effect when --section is not specified
	if len(flagSections) == 0 {
		bm := strings.ToLower(strings.TrimSpace(flagBenchmark))
		if bm != "" && bm != "all" {
			if secs, ok := benchmarkSections[bm]; ok {
				sections = secs
			} else {
				return fmt.Errorf("unknown benchmark %q; valid: all, cis, nsa, pci-dss", flagBenchmark)
			}
		}
		// "all" = no filter (all sections)
	} else {
		for _, s := range flagSections {
			for _, part := range strings.Split(s, ",") {
				sections = append(sections, rules.CISSection(strings.TrimSpace(part)))
			}
		}
	}

	// Scan files
	opts := scanner.ScanOptions{
		Paths:     args,
		Recursive: flagRecursive,
	}
	objects, parseErrors, err := scanner.Scan(opts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if len(parseErrors) > 0 {
		for _, pe := range parseErrors {
			fmt.Fprintf(os.Stderr, "warning: %s: %s\n", pe.File, pe.Message)
		}
	}

	// Build checker config
	cfg := checker.Config{
		IgnoreRules: flagIgnore,
		Sections:    sections,
		MinSeverity: rules.Severity(strings.ToUpper(flagMinSeverity)),
	}

	// Run checks
	results := checker.Run(objects, cfg)

	// Collect scanned file paths
	fileSet := map[string]bool{}
	for _, obj := range objects {
		if obj.SourceFile != "" {
			fileSet[obj.SourceFile] = true
		}
	}
	var files []string
	for f := range fileSet {
		files = append(files, f)
	}

	// Build report
	rep := report.New(results, files)

	// Output
	switch strings.ToLower(flagOutput) {
	case "json":
		if err := report.WriteJSON(os.Stdout, rep); err != nil {
			return err
		}
	case "table":
		report.WriteTable(os.Stdout, rep, flagVerbose)
	case "html":
		if err := report.WriteHTML(os.Stdout, rep); err != nil {
			return err
		}
	default:
		report.WriteText(os.Stdout, rep, flagVerbose)
	}

	// Exit code logic
	failCount := rep.FailCount()
	if flagFailOnScore > 0 && int(rep.Score.Score) < flagFailOnScore {
		os.Exit(1)
	}
	if failCount > 0 {
		os.Exit(1)
	}

	return nil
}
