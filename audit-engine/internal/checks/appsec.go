package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/appsec"
)

// RunAppSecChecks runs an optional application security scanner
// and converts its results into native Auditor findings.
func RunAppSecChecks(
	ctx context.Context,
	scanner appsec.Scanner,
	config appsec.ScannerConfig,
) Report {
	report := NewReport()

	if scanner == nil {
		report.Add(Finding{
			ID:       "APPSEC000",
			Category: "application",
			Status:   StatusError,
			Severity: "medium",
			Message:  "No application security scanner was configured.",
		})
		return report
	}

	source := scanner.Name()

	if !scanner.Available(ctx) {
		report.Add(Finding{
			ID:             "APPSEC000",
			Source:         source,
			Category:       "application",
			Asset:          config.TargetPath,
			Status:         StatusPass,
			Severity:       "info",
			Message:        fmt.Sprintf("%s CLI is unavailable; application security scan was skipped.", source),
			Description:    "Application security scanning is optional and was not executed.",
			Recommendation: "Install and configure the scanner if application dependency scanning is required.",
		})
		return report
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
		return report
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
			Asset:          result.TargetPath,
			Status:         StatusError,
			Severity:       "medium",
			Message:        "Application security scan failed: " + message,
			Description:    "The scanner returned an unsuccessful scan result.",
			Recommendation: "Review scanner output and verify the target project and scanner configuration.",
		})
		return report
	}

	if len(result.Vulnerabilities) == 0 {
		report.Add(Finding{
			ID:          "APPSEC001",
			Source:      source,
			Category:    "application",
			Asset:       result.TargetPath,
			Status:      StatusPass,
			Severity:    "info",
			Message:     "No dependency vulnerabilities were reported.",
			Description: "The application security scanner completed without reporting vulnerabilities.",
			Evidence: map[string]any{
				"scanner":     source,
				"target_path": result.TargetPath,
			},
		})
		return report
	}

	for i, vulnerability := range result.Vulnerabilities {
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

		id := vulnerability.ID
		if id == "" {
			id = fmt.Sprintf("finding-%d", i+1)
		}

		description := vulnerability.Description
		if description == "" {
			description = vulnerability.Title
		}

		recommendation := vulnerability.Recommendation
		if recommendation == "" && vulnerability.FixedVersion != "" {
			recommendation = "Upgrade to version " + vulnerability.FixedVersion + " or a compatible patched version."
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
				"package_name":     vulnerability.PackageName,
				"package_version":  vulnerability.PackageVersion,
				"fixed_version":    vulnerability.FixedVersion,
				"references":       vulnerability.References,
				"details":          vulnerability.Evidence,
			},
		})
	}

	return report
}
