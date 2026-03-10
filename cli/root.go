package cli

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "compliancevet",
	Short: "Kubernetes compliance checker for CIS Benchmark and industry standards",
	Long: `ComplianceVet automatically evaluates Kubernetes manifests against
CIS Kubernetes Benchmark v1.9, NSA/CISA Hardening Guide, PCI-DSS, and more.`,
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(clusterCmd)
	rootCmd.AddCommand(versionCmd)
}
