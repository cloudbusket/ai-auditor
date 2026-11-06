package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
	"github.com/spf13/cobra"
)

var kubernetesFormat string

var kubernetesCmd = &cobra.Command{
	Use:   "kubernetes",
	Short: "Run Kubernetes security and health checks",
	Long:  "Collect Kubernetes cluster inventory and run read-only Kubernetes security checks.",
	RunE: func(cmd *cobra.Command, args []string) error {
		report := checks.RunKubernetesChecks()

		switch strings.ToLower(kubernetesFormat) {
		case "json":
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(report)

		case "text":
			out := cmd.OutOrStdout()

			fmt.Fprintf(out, "Kubernetes health: %s\n", report.OverallStatus)
			fmt.Fprintf(
				out,
				"Passed: %d | Warnings: %d | Critical: %d | Errors: %d\n\n",
				report.Summary.Passed,
				report.Summary.Warnings,
				report.Summary.Critical,
				report.Summary.Errors,
			)

			for _, finding := range report.Findings {
				fmt.Fprintf(
					out,
					"[%s] %s: %s\n",
					strings.ToUpper(string(finding.Status)),
					finding.ID,
					finding.Message,
				)

				if finding.Recommendation != "" {
					fmt.Fprintf(out, "  Recommendation: %s\n", finding.Recommendation)
				}
			}

			return nil

		default:
			return fmt.Errorf(
				"unsupported format %q: use json or text",
				kubernetesFormat,
			)
		}
	},
}

func init() {
	kubernetesCmd.Flags().StringVar(
		&kubernetesFormat,
		"format",
		"text",
		"Output format: text or json",
	)

	rootCmd.AddCommand(kubernetesCmd)
}
