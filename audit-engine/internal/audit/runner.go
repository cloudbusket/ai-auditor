package audit

import (
	"context"
	"strings"
	"time"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/appsec"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
)

// Config defines the settings for a consolidated audit.
type Config struct {
	TargetPath string
	Timeout    time.Duration
}

// Run executes infrastructure and optional application security checks.
// It does not install or authenticate external scanners.
func Run(
	ctx context.Context,
	scanner appsec.Scanner,
	config Config,
) checks.Report {
	report := checks.NewReport()

	// Infrastructure assessment: host, Docker and Kubernetes.
	infrastructureStarted := time.Now().UTC()
	infrastructureReport := checks.RunHostChecks()
	infrastructureCompleted := time.Now().UTC()

	infrastructureStatus := checks.ModuleCompleted
	infrastructureMessage := "Host, Docker and Kubernetes checks were executed."

	for _, finding := range infrastructureReport.Findings {
		report.Add(finding)

		if finding.Status == checks.StatusError {
			infrastructureStatus = checks.ModuleFailed
			infrastructureMessage = "Infrastructure assessment encountered an error."
		}
	}

	report.AddModule(checks.ModuleResult{
		Name:        "infrastructure",
		Status:      infrastructureStatus,
		Message:     infrastructureMessage,
		StartedAt:   infrastructureStarted,
		CompletedAt: infrastructureCompleted,
		DurationMs:  infrastructureCompleted.Sub(infrastructureStarted).Milliseconds(),
	})

	// Optional application security assessment.
	appsecStarted := time.Now().UTC()

	scannerAvailable := scanner != nil && scanner.Available(ctx)

	appsecReport := checks.RunAppSecChecks(
		ctx,
		scanner,
		appsec.ScannerConfig{
			TargetPath: config.TargetPath,
			Timeout:    config.Timeout,
		},
	)

	appsecCompleted := time.Now().UTC()

	appsecStatus := checks.ModuleCompleted
	appsecMessage := "Application security scan completed."

	switch {
	case scanner == nil:
		appsecStatus = checks.ModuleFailed
		appsecMessage = "No application security scanner was configured."

	case !scannerAvailable:
		appsecStatus = checks.ModuleSkipped
		appsecMessage = "Application security scanner is unavailable; scanning was skipped."

	default:
		for _, finding := range appsecReport.Findings {
			if finding.Status == checks.StatusError {
				appsecStatus = checks.ModuleFailed
				appsecMessage = "Application security scan encountered an error."
				break
			}
		}
	}

	report.AddModule(checks.ModuleResult{
		Name:        "appsec",
		Status:      appsecStatus,
		Message:     appsecMessage,
		StartedAt:   appsecStarted,
		CompletedAt: appsecCompleted,
		DurationMs:  appsecCompleted.Sub(appsecStarted).Milliseconds(),
	})

	for _, finding := range appsecReport.Findings {
		if !scannerAvailable && scanner != nil &&
			strings.EqualFold(scanner.Name(), "snyk") &&
			finding.ID == "APPSEC000" {
			finding.Recommendation =
				"Install Snyk with: npm install --global snyk. Then authenticate with: snyk auth."
		}

		report.Add(finding)
	}

	return report
}
