package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
	"github.com/spf13/cobra"
)

var checkFormat string

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Run infrastructure health checks",
	Long:  "Check Linux disk usage, memory utilization, and failed services.",
	RunE: func(cmd *cobra.Command, args []string) error {
		report := checks.RunHostChecks()

		switch strings.ToLower(checkFormat) {
		case "json":
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(report)

		case "text":
			out := cmd.OutOrStdout()

			fmt.Fprintf(out, "Infrastructure health: %s\n",
				report.OverallStatus)
			fmt.Fprintf(out,
				"Passed: %d | Warnings: %d | Critical: %d | Errors: %d\n\n",
				report.Summary.Passed,
				report.Summary.Warnings,
				report.Summary.Critical,
				report.Summary.Errors,
			)

			for _, f := range report.Findings {
				fmt.Fprintf(out, "[%s] %s: %s\n",
					strings.ToUpper(string(f.Status)), f.ID, f.Message)
				if f.Recommendation != "" {
					fmt.Fprintf(out, "  Recommendation: %s\n",
						f.Recommendation)
				}
			}
			return nil

		default:
			return fmt.Errorf(
				"unsupported format %q: use json or text", checkFormat)
		}
	},
}

func init() {
	checkCmd.Flags().StringVar(
		&checkFormat, "format", "text", "Output format: text or json",
	)
	rootCmd.AddCommand(checkCmd)
}
