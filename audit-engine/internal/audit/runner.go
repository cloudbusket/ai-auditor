package audit

import (
	"context"
	"strings"
	"time"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/appsec"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/cloud"
)

// Config defines the settings for a consolidated audit.
type Config struct {
	TargetPath     string
	Timeout        time.Duration
	CloudCollector cloud.Collector
	CloudConfig    cloud.Config
}

// Run executes infrastructure, optional application security,
// and optional cloud discovery checks.
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

	// Optional cloud discovery. It runs only when a project ID
	// or a cloud collector has been explicitly configured.
	if config.CloudConfig.ProjectID != "" || config.CloudCollector != nil {
		runCloudDiscovery(ctx, &report, config)
	}

	return report
}

func runCloudDiscovery(
	ctx context.Context,
	report *checks.Report,
	config Config,
) {
	started := time.Now().UTC()

	if config.CloudCollector == nil {
		completed := time.Now().UTC()

		report.AddModule(checks.ModuleResult{
			Name:        "cloud_discovery",
			Status:      checks.ModuleFailed,
			Message:     "A cloud project was specified, but no cloud collector was configured.",
			StartedAt:   started,
			CompletedAt: completed,
			DurationMs:  completed.Sub(started).Milliseconds(),
		})
		return
	}

	inventory, err := config.CloudCollector.Discover(ctx, config.CloudConfig)
	completed := time.Now().UTC()

	// Preserve any inventory and coverage returned, even if discovery
	// reports an error.
	report.CloudInventory = &inventory

	for _, item := range inventory.Coverage {
		report.AddCoverage(checks.Coverage{
			Provider:      string(item.Provider),
			Category:      item.Category,
			Status:        checks.CoverageStatus(item.Status),
			ResourceCount: item.ResourceCount,
			Message:       item.Message,
			StartedAt:     item.StartedAt,
			CompletedAt:   item.CompletedAt,
			DurationMs:    item.DurationMs,
		})
	}

	moduleStatus := checks.ModuleCompleted
	moduleMessage := "Cloud resource discovery completed."

	if err != nil {
		moduleStatus = checks.ModuleFailed
		moduleMessage = "Cloud resource discovery failed: " + err.Error()
	} else {
		for _, item := range inventory.Coverage {
			if item.Status != cloud.CoverageCompleted &&
				item.Status != cloud.CoverageNoData {
				moduleMessage = "Cloud discovery completed with collection coverage gaps."
				break
			}
		}
	}

	report.AddModule(checks.ModuleResult{
		Name:        "cloud_discovery",
		Status:      moduleStatus,
		Message:     moduleMessage,
		StartedAt:   started,
		CompletedAt: completed,
		DurationMs:  completed.Sub(started).Milliseconds(),
	})
}
