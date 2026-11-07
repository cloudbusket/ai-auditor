package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/appsec"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
	"github.com/spf13/cobra"
)

var (
	appsecTarget  string
	appsecFormat  string
	appsecTimeout time.Duration
)

var appsecCmd = &cobra.Command{
	Use:   "appsec",
	Short: "Run application and dependency security checks",
	Long:  "Run application dependency vulnerability checks using the optional Snyk CLI.",

	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		scanner, err := prepareSnyk(
			ctx,
			cmd.InOrStdin(),
			cmd.OutOrStdout(),
			cmd.ErrOrStderr(),
			strings.EqualFold(appsecFormat, "text") &&
				isInteractiveInput(cmd.InOrStdin()),
		)
		if err != nil {
			return err
		}

		report := checks.RunAppSecChecks(
			ctx,
			scanner,
			appsec.ScannerConfig{
				TargetPath: appsecTarget,
				Timeout:    appsecTimeout,
			},
		)

		if !scanner.Available(ctx) {
			for i := range report.Findings {
				if report.Findings[i].ID == "APPSEC000" {
					report.Findings[i].Recommendation =
						"Install Snyk with: npm install --global snyk. Then authenticate with: snyk auth."
				}
			}
		}

		switch strings.ToLower(appsecFormat) {
		case "json":
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(report)

		case "text":
			out := cmd.OutOrStdout()

			fmt.Fprintf(out, "Application security: %s\n", report.OverallStatus)
			fmt.Fprintf(out, "Passed: %d | Warnings: %d | Critical: %d | Errors: %d\n\n",
				report.Summary.Passed,
				report.Summary.Warnings,
				report.Summary.Critical,
				report.Summary.Errors,
			)

			for _, finding := range report.Findings {
				fmt.Fprintf(out, "[%s] %s (%s): %s\n",
					strings.ToUpper(string(finding.Status)),
					finding.ID,
					finding.Source,
					finding.Message,
				)

				if finding.Asset != "" {
					fmt.Fprintf(out, "  Asset: %s\n", finding.Asset)
				}

				if finding.Recommendation != "" {
					fmt.Fprintf(out, "  Recommendation: %s\n", finding.Recommendation)
				}
			}

			return nil

		default:
			return fmt.Errorf("unsupported format %q: use json or text", appsecFormat)
		}
	},
}

func init() {
	appsecCmd.Flags().StringVar(&appsecTarget, "target", ".", "Application project directory to scan")
	appsecCmd.Flags().StringVar(&appsecFormat, "format", "text", "Output format: text or json")
	appsecCmd.Flags().DurationVar(&appsecTimeout, "timeout", 5*time.Minute, "Maximum scanner execution time")

	rootCmd.AddCommand(appsecCmd)
}
