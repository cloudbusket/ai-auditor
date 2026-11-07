package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/audit"
	"github.com/spf13/cobra"
)

var (
	scanTarget  string
	scanFormat  string
	scanTimeout time.Duration
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a consolidated infrastructure and application audit",
	Long: `Run host, Docker, Kubernetes and optional application dependency
security checks and combine their findings into one audit report.`,

	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		if !strings.EqualFold(scanFormat, "json") &&
			!strings.EqualFold(scanFormat, "text") {
			return fmt.Errorf("unsupported format %q: use json or text", scanFormat)
		}

		fmt.Fprintln(cmd.ErrOrStderr(), "Starting CloudBusket AI Auditor scan...")

		scanner, err := prepareSnyk(
			ctx,
			cmd.InOrStdin(),
			cmd.OutOrStdout(),
			cmd.ErrOrStderr(),
			strings.EqualFold(scanFormat, "text") &&
				isInteractiveInput(cmd.InOrStdin()),
		)
		if err != nil {
			return err
		}

		report := audit.Run(ctx, scanner, audit.Config{
			TargetPath: scanTarget,
			Timeout:    scanTimeout,
		})

		switch strings.ToLower(scanFormat) {
		case "json":
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(report)

		case "text":
			out := cmd.OutOrStdout()

			fmt.Fprintln(out, "\nCloudBusket AI Auditor")
			fmt.Fprintln(out, "======================")
			fmt.Fprintf(out, "Overall status: %s\n",
				strings.ToUpper(string(report.OverallStatus)))
			fmt.Fprintf(out, "Passed: %d | Warnings: %d | Critical: %d | Errors: %d\n\n",
				report.Summary.Passed,
				report.Summary.Warnings,
				report.Summary.Critical,
				report.Summary.Errors,
			)

			fmt.Fprintln(out, "Module execution:")
			for _, module := range report.Modules {
				fmt.Fprintf(out, "[%s] %s: %s (%d ms)\n",
					strings.ToUpper(string(module.Status)),
					module.Name,
					module.Message,
					module.DurationMs,
				)
			}

			fmt.Fprintln(out, "\nFindings:")
			for _, finding := range report.Findings {
				fmt.Fprintf(out, "[%s] %s [%s] %s\n",
					strings.ToUpper(string(finding.Status)),
					finding.ID,
					finding.Category,
					finding.Message,
				)

				if finding.Asset != "" {
					fmt.Fprintf(out, "  Asset: %s\n", finding.Asset)
				}

				if finding.Recommendation != "" {
					fmt.Fprintf(out, "  Recommendation: %s\n",
						finding.Recommendation)
				}
			}

			fmt.Fprintf(out, "\nTotal findings: %d\n", len(report.Findings))
			return nil
		}

		return nil
	},
}

func init() {
	scanCmd.Flags().StringVar(&scanTarget, "target", ".", "Application project directory to scan")
	scanCmd.Flags().StringVar(&scanFormat, "format", "text", "Output format: text or json")
	scanCmd.Flags().DurationVar(&scanTimeout, "timeout", 5*time.Minute, "Maximum application scanner execution time")

	rootCmd.AddCommand(scanCmd)
}
