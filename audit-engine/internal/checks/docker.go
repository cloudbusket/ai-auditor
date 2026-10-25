package checks

import (
	"fmt"
	"strings"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
)

func checkDocker(report *Report, inv *inventory.Inventory) {
	if inv.Docker == nil {
		report.Add(Finding{
			ID:             "DCK001",
			Category:       "docker",
			Status:         StatusWarning,
			Severity:       "medium",
			Message:        "Docker inventory is unavailable.",
			Recommendation: "Check Docker inventory collection and auditor permissions.",
		})
		return
	}

	d := inv.Docker

	if !d.CLIAvailable {
		report.Add(Finding{
			ID:       "DCK001",
			Category: "docker",
			Status:   StatusPass,
			Severity: "info",
			Message:  "Docker CLI is not installed; Docker checks were skipped.",
		})
		return
	}

	if !d.DaemonAvailable {
		message := "Docker CLI is installed, but the Docker daemon is unavailable."
		if d.Error != "" {
			message += " " + d.Error
		}
		report.Add(Finding{
			ID:             "DCK001",
			Category:       "docker",
			Status:         StatusWarning,
			Severity:       "medium",
			Message:        message,
			Recommendation: "Check `systemctl status docker` and inspect `journalctl -u docker`.",
		})
		return
	}

	report.Add(Finding{
		ID:       "DCK001",
		Category: "docker",
		Status:   StatusPass,
		Severity: "info",
		Message:  "Docker CLI is installed and the daemon is reachable.",
	})

	var unhealthy []string
	var stopped []string

	for _, c := range d.Containers {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			name = c.ID
		}
		if name == "" {
			name = "unnamed container"
		}

		if strings.EqualFold(c.Health, "unhealthy") ||
			strings.Contains(strings.ToLower(c.Status), "(unhealthy)") {
			unhealthy = append(unhealthy, name)
		}

		if !c.Running {
			state := strings.ToLower(strings.TrimSpace(c.State))
			if state == "exited" || state == "created" || state == "dead" {
				stopped = append(stopped, name+" ("+state+")")
			}
		}
	}

	if len(unhealthy) > 0 {
		report.Add(Finding{
			ID:       "DCK002",
			Category: "docker",
			Status:   StatusCritical,
			Severity: "high",
			Message:  fmt.Sprintf("Unhealthy Docker containers: %s.", strings.Join(unhealthy, ", ")),
			Recommendation: "Inspect each container with `docker inspect` and review its " +
				"logs using `docker logs <container>`.",
		})
	} else {
		report.Add(Finding{
			ID:       "DCK002",
			Category: "docker",
			Status:   StatusPass,
			Severity: "info",
			Message:  "No containers reporting an unhealthy health check were found.",
		})
	}

	if len(stopped) > 0 {
		report.Add(Finding{
			ID:       "DCK003",
			Category: "docker",
			Status:   StatusWarning,
			Severity: "medium",
			Message:  fmt.Sprintf("Stopped Docker containers found: %s.", strings.Join(stopped, ", ")),
			Recommendation: "Confirm whether these containers should be running. " +
				"Review their exit status and restart policy before taking action.",
		})
	} else {
		report.Add(Finding{
			ID:       "DCK003",
			Category: "docker",
			Status:   StatusPass,
			Severity: "info",
			Message:  "No stopped, exited, created, or dead containers were found.",
		})
	}

	if d.Error != "" && d.DaemonAvailable {
		report.Add(Finding{
			ID:             "DCK004",
			Category:       "docker",
			Status:         StatusWarning,
			Severity:       "medium",
			Message:        "Docker inventory is incomplete: " + d.Error,
			Recommendation: "Review Docker command errors and verify the auditor can query containers, images, networks, and volumes.",
		})
	}
}
