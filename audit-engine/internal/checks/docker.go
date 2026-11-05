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
			Asset:          "Docker daemon",
			Status:         StatusWarning,
			Severity:       "medium",
			Message:        "Docker inventory is unavailable.",
			Description:    "The auditor could not obtain Docker inventory information.",
			Recommendation: "Check Docker inventory collection and auditor permissions.",
			Evidence: map[string]any{
				"inventory_available": false,
				"cli_available":       false,
				"daemon_available":    false,
			},
		})
		return
	}

	d := inv.Docker

	dockerEvidence := map[string]any{
		"installed":        d.Installed,
		"cli_available":    d.CLIAvailable,
		"daemon_available": d.DaemonAvailable,
		"error":            d.Error,
		"version": map[string]any{
			"version":      d.Version.Version,
			"api_version":  d.Version.APIVersion,
			"go_version":   d.Version.GoVersion,
			"git_commit":   d.Version.GitCommit,
			"build_time":   d.Version.BuildTime,
			"experimental": d.Version.Experimental,
		},
	}

	if !d.CLIAvailable {
		report.Add(Finding{
			ID:          "DCK001",
			Category:    "docker",
			Asset:       "Docker CLI",
			Status:      StatusPass,
			Severity:    "info",
			Message:     "Docker CLI is not installed; Docker checks were skipped.",
			Description: "Docker command-line tooling was not detected on this host.",
			Evidence:    dockerEvidence,
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
			Asset:          "Docker daemon",
			Status:         StatusWarning,
			Severity:       "medium",
			Message:        message,
			Description:    "The Docker CLI is available, but the auditor could not reach the Docker daemon.",
			Recommendation: "Check `systemctl status docker` and inspect `journalctl -u docker`.",
			Evidence:       dockerEvidence,
		})
		return
	}

	report.Add(Finding{
		ID:          "DCK001",
		Category:    "docker",
		Asset:       "Docker daemon",
		Status:      StatusPass,
		Severity:    "info",
		Message:     "Docker CLI is installed and the daemon is reachable.",
		Description: "The auditor successfully detected the Docker CLI and reached the Docker daemon.",
		Evidence:    dockerEvidence,
	})

	var unhealthy []string
	var stopped []string

	var unhealthyEvidence []map[string]any
	var stoppedEvidence []map[string]any

	for _, c := range d.Containers {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			name = c.ID
		}
		if name == "" {
			name = "unnamed container"
		}

		containerEvidence := map[string]any{
			"id":      c.ID,
			"name":    name,
			"image":   c.Image,
			"state":   c.State,
			"status":  c.Status,
			"running": c.Running,
			"health":  c.Health,
		}

		if strings.EqualFold(c.Health, "unhealthy") ||
			strings.Contains(strings.ToLower(c.Status), "(unhealthy)") {
			unhealthy = append(unhealthy, name)
			unhealthyEvidence = append(unhealthyEvidence, containerEvidence)
		}

		if !c.Running {
			state := strings.ToLower(strings.TrimSpace(c.State))
			if state == "exited" || state == "created" || state == "dead" {
				stopped = append(stopped, name+" ("+state+")")
				stoppedEvidence = append(stoppedEvidence, containerEvidence)
			}
		}
	}

	if len(unhealthy) > 0 {
		report.Add(Finding{
			ID:       "DCK002",
			Category: "docker",
			Asset:    "Docker containers",
			Status:   StatusCritical,
			Severity: "high",
			Message: fmt.Sprintf(
				"Unhealthy Docker containers: %s.",
				strings.Join(unhealthy, ", "),
			),
			Description: "One or more Docker containers are reporting an unhealthy health-check status.",
			Recommendation: "Inspect each container with docker inspect and review its " +
				"logs using docker logs. Investigate the health-check failure before restarting the container.",
			Evidence: map[string]any{
				"unhealthy_count": len(unhealthyEvidence),
				"containers":      unhealthyEvidence,
			},
		})
	} else {
		report.Add(Finding{
			ID:          "DCK002",
			Category:    "docker",
			Asset:       "Docker containers",
			Status:      StatusPass,
			Severity:    "info",
			Message:     "No containers reporting an unhealthy health check were found.",
			Description: "No unhealthy container health checks were detected in the collected Docker inventory.",
			Evidence: map[string]any{
				"unhealthy_count": 0,
				"containers":      []map[string]any{},
			},
		})
	}

	if len(stopped) > 0 {
		report.Add(Finding{
			ID:       "DCK003",
			Category: "docker",
			Asset:    "Docker containers",
			Status:   StatusWarning,
			Severity: "medium",
			Message: fmt.Sprintf(
				"Stopped Docker containers found: %s.",
				strings.Join(stopped, ", "),
			),
			Description: "One or more Docker containers are stopped, exited, created, or dead.",
			Recommendation: "Confirm whether these containers should be running. " +
				"Review their exit status and restart policy before taking action.",
			Evidence: map[string]any{
				"stopped_count": len(stoppedEvidence),
				"containers":    stoppedEvidence,
			},
		})
	} else {
		report.Add(Finding{
			ID:          "DCK003",
			Category:    "docker",
			Asset:       "Docker containers",
			Status:      StatusPass,
			Severity:    "info",
			Message:     "No stopped, exited, created, or dead containers were found.",
			Description: "No stopped containers were detected in the collected Docker inventory.",
			Evidence: map[string]any{
				"stopped_count": 0,
				"containers":    []map[string]any{},
			},
		})
	}

	if d.Error != "" && d.DaemonAvailable {
		report.Add(Finding{
			ID:             "DCK004",
			Category:       "docker",
			Asset:          "Docker inventory",
			Status:         StatusWarning,
			Severity:       "medium",
			Message:        "Docker inventory is incomplete: " + d.Error,
			Description:    "One or more Docker inventory collection operations failed even though the Docker daemon is reachable.",
			Recommendation: "Review Docker command errors and verify the auditor can query containers, images, networks, and volumes.",
			Evidence: map[string]any{
				"error":               d.Error,
				"cli_available":       d.CLIAvailable,
				"daemon_available":    d.DaemonAvailable,
				"container_count":     len(d.Containers),
				"image_count":         len(d.Images),
				"network_count":       len(d.Networks),
				"volume_count":        len(d.Volumes),
				"storage_entry_count": len(d.Storage),
			},
		})
	}

	// DCK005: report Docker storage usage without deleting anything.
	if len(d.Storage) == 0 {
		report.Add(Finding{
			ID:             "DCK005",
			Category:       "docker",
			Asset:          "Docker storage",
			Status:         StatusWarning,
			Severity:       "medium",
			Message:        "Docker storage usage could not be collected.",
			Description:    "The auditor could not retrieve Docker storage utilization information.",
			Recommendation: "Check `docker system df` and Docker permissions.",
			Evidence: map[string]any{
				"storage_entry_count": 0,
				"storage":             []map[string]any{},
			},
		})
	} else {
		var details []string
		var storageEvidence []map[string]any

		for _, item := range d.Storage {
			details = append(details, fmt.Sprintf(
				"%s: %s used, %s reclaimable (%s items, %s active)",
				item.Type, item.Size, item.Reclaimable,
				item.TotalCount, item.Active,
			))

			storageEvidence = append(storageEvidence, map[string]any{
				"type":        item.Type,
				"total_count": item.TotalCount,
				"active":      item.Active,
				"size":        item.Size,
				"reclaimable": item.Reclaimable,
			})
		}

		report.Add(Finding{
			ID:          "DCK005",
			Category:    "docker",
			Asset:       "Docker storage",
			Status:      StatusPass,
			Severity:    "info",
			Message:     "Docker storage usage: " + strings.Join(details, "; ") + ".",
			Description: "Docker storage utilization was successfully collected.",
			Recommendation: "Review reclaimable resources before manual cleanup. " +
				"The auditor does not delete Docker resources.",
			Evidence: map[string]any{
				"storage_entry_count": len(storageEvidence),
				"storage":             storageEvidence,
			},
		})
	}

	// DCK006: assess the filesystem containing Docker's data directory.
	dockerFilesystemEvidence := map[string]any{
		"docker_root_dir":         d.DockerRootDir,
		"filesystem_size_gb":      d.FilesystemSizeGB,
		"filesystem_used_gb":      d.FilesystemUsedGB,
		"filesystem_free_gb":      d.FilesystemFreeGB,
		"filesystem_used_percent": d.FilesystemUsedPercent,
	}

	switch {
	case d.DockerRootDir == "":
		report.Add(Finding{
			ID:             "DCK006",
			Category:       "docker",
			Asset:          "Docker filesystem",
			Status:         StatusWarning,
			Severity:       "medium",
			Message:        "Docker data-directory filesystem usage could not be determined.",
			Description:    "The auditor could not determine filesystem capacity for Docker's data directory.",
			Recommendation: "Verify Docker data-directory access and filesystem statistics.",
			Evidence:       dockerFilesystemEvidence,
		})

	case d.FilesystemUsedPercent >= 90:
		report.Add(Finding{
			ID:       "DCK006",
			Category: "docker",
			Asset:    "Docker filesystem",
			Status:   StatusCritical,
			Severity: "high",
			Message: fmt.Sprintf(
				"Filesystem backing Docker data directory %s is %d%% full (%d GB used of %d GB).",
				d.DockerRootDir, d.FilesystemUsedPercent,
				d.FilesystemUsedGB, d.FilesystemSizeGB,
			),
			Description:    "The filesystem containing Docker's data directory has reached critical capacity.",
			Recommendation: "Investigate filesystem growth urgently and review Docker storage before taking cleanup action.",
			Evidence:       dockerFilesystemEvidence,
		})

	case d.FilesystemUsedPercent >= 80:
		report.Add(Finding{
			ID:       "DCK006",
			Category: "docker",
			Asset:    "Docker filesystem",
			Status:   StatusWarning,
			Severity: "medium",
			Message: fmt.Sprintf(
				"Filesystem backing Docker data directory %s is %d%% full (%d GB used of %d GB).",
				d.DockerRootDir, d.FilesystemUsedPercent,
				d.FilesystemUsedGB, d.FilesystemSizeGB,
			),
			Description:    "The filesystem containing Docker's data directory is approaching critical capacity.",
			Recommendation: "Monitor disk growth and review Docker storage before the filesystem reaches critical capacity.",
			Evidence:       dockerFilesystemEvidence,
		})

	default:
		report.Add(Finding{
			ID:       "DCK006",
			Category: "docker",
			Asset:    "Docker filesystem",
			Status:   StatusPass,
			Severity: "info",
			Message: fmt.Sprintf(
				"Filesystem backing Docker data directory %s is %d%% full.",
				d.DockerRootDir, d.FilesystemUsedPercent,
			),
			Description: "The filesystem containing Docker's data directory is below the warning threshold.",
			Evidence:    dockerFilesystemEvidence,
		})
	}
}
