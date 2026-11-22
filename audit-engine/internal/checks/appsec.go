package checks

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/appsec"
	"strings"
	"time"
)

// RunAppSecChecks runs an optional application security scanner
// and converts its results into native Auditor findings.
func RunAppSecChecks(ctx context.Context, scanner appsec.Scanner, config appsec.ScannerConfig) Report {
	report := NewReport()
	startedAt := time.Now().UTC()

	finish := func(status ModuleStatus, message string) Report {
		completedAt := time.Now().UTC()
		report.AddModule(ModuleResult{
			Name:        "appsec",
			Status:      status,
			Message:     message,
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			DurationMs:  completedAt.Sub(startedAt).Milliseconds(),
		})
		return report
	}

	if scanner == nil {
		report.Add(Finding{
			ID:             "APPSEC000",
			Category:       "application",
			Status:         StatusError,
			Severity:       "medium",
			Message:        "No application security scanner was configured.",
			Description:    "Application security scanning could not be started.",
			Recommendation: "Configure an application security scanner before running this check.",
		})
		return finish(ModuleFailed, "No application security scanner was configured.")
	}

	source := scanner.Name()

	if err := ctx.Err(); err != nil {
		report.Add(Finding{
			ID:             "APPSEC000",
			Source:         source,
			Category:       "application",
			Asset:          config.TargetPath,
			Status:         StatusError,
			Severity:       "medium",
			Message:        "Application security scan could not start: " + err.Error(),
			Description:    "The application security scan was cancelled or its context deadline expired.",
			Recommendation: "Retry the scan with an active context and sufficient timeout.",
		})
		return finish(ModuleFailed, "Application security scan was cancelled or timed out.")
	}

	if !scanner.Available(ctx) {
		return finish(ModuleSkipped, source+" CLI is unavailable; application security scanning was skipped.")
	}

	result, err := scanner.Scan(ctx, config)
	if err != nil {
		report.Add(Finding{
			ID:             "APPSEC000",
			Source:         source,
			Category:       "application",
			Asset:          config.TargetPath,
			Status:         StatusError,
			Severity:       "medium",
			Message:        "Application security scan failed: " + err.Error(),
			Description:    "The configured scanner could not complete the application security assessment.",
			Recommendation: "Check scanner authentication, target path, network connectivity, and timeout settings.",
		})
		return finish(ModuleFailed, "Application security scan failed.")
	}

	if result.Scanner != "" {
		source = result.Scanner
	}

	if !result.Success {
		message := result.Error
		if message == "" {
			message = "The scanner did not complete successfully."
		}

		report.Add(Finding{
			ID:             "APPSEC000",
			Source:         source,
			Category:       "application",
			Asset:          config.TargetPath,
			Status:         StatusError,
			Severity:       "medium",
			Message:        "Application security scan failed: " + message,
			Description:    "The configured scanner could not complete the application security assessment.",
			Recommendation: "Check scanner authentication, target path, network connectivity, and timeout settings.",
		})
		return finish(ModuleFailed, "Application security scan failed.")
	}

	if len(result.Vulnerabilities) == 0 {
		report.Add(Finding{
			ID:       "APPSEC001",
			Source:   source,
			Category: "application",
			Asset:    result.TargetPath,
			Status:   StatusPass,
			Severity: "info",
			Message:  "No application dependency vulnerabilities were found.",
		})
		return finish(ModuleCompleted, "Application security scan completed successfully.")
	}

	for _, vulnerability := range result.Vulnerabilities {
		severity := strings.ToLower(strings.TrimSpace(vulnerability.Severity))
		status := StatusWarning

		switch severity {
		case "critical", "high":
			status = StatusCritical
		}

		asset := result.TargetPath
		if vulnerability.PackageName != "" {
			asset = vulnerability.PackageName
			if vulnerability.PackageVersion != "" {
				asset += "@" + vulnerability.PackageVersion
			}
		}

		id := strings.TrimSpace(vulnerability.ID)
		if id == "" {
			fallback := strings.Join([]string{
				strings.TrimSpace(vulnerability.PackageName),
				strings.TrimSpace(vulnerability.PackageVersion),
				strings.TrimSpace(vulnerability.Title),
			}, "|")

			id = fmt.Sprintf("UNKNOWN-%x", sha256.Sum256([]byte(fallback)))

		}

		description := vulnerability.Description
		if description == "" {
			description = vulnerability.Title
		}

		recommendation := vulnerability.Recommendation
		if recommendation == "" && vulnerability.FixedVersion != "" {
			recommendation = "Upgrade to version " + vulnerability.FixedVersion + " or later."
		}

		report.Add(Finding{
			ID:             "APPSEC-VULN-" + id,
			Source:         source,
			Category:       "application",
			Asset:          asset,
			Status:         status,
			Severity:       severity,
			Message:        vulnerability.Title,
			Description:    description,
			Recommendation: recommendation,
			Evidence: map[string]any{
				"scanner":          source,
				"vulnerability_id": vulnerability.ID,
				"package":          vulnerability.PackageName,
				"version":          vulnerability.PackageVersion,
				"fixed_version":    vulnerability.FixedVersion,
				"references":       vulnerability.References,
				"details":          vulnerability.Evidence,
			},
		})
	}

	return finish(ModuleCompleted, "Application security scan completed; vulnerabilities were found.")
}
