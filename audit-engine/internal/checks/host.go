package checks

import (
	"fmt"
	"strings"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
	"github.com/shirou/gopsutil/v3/mem"
)

func RunHostChecks() Report {
	report := NewReport()

	inv, err := inventory.Collect()
	if err != nil {
		report.Add(Finding{
			ID:       "HOST001",
			Category: "host",
			Status:   StatusError,
			Severity: "high",
			Message:  "Unable to collect host inventory: " + err.Error(),
			Recommendation: "Check the auditor's permissions and inspect " +
				"the inventory collector errors.",
		})
		return report
	}

	checkRootDisk(&report, inv)
	checkMemory(&report)
	checkServices(&report, inv)
	checkDocker(&report, inv)
	checkKubernetes(&report, inv)

	return report
}
func checkRootDisk(report *Report, inv *inventory.Inventory) {
	var root *inventory.DiskInfo

	for i := range inv.Disk {
		if inv.Disk[i].Mount == "/" {
			root = &inv.Disk[i]
			break
		}
	}

	if root == nil {
		report.Add(Finding{
			ID:          "DISK001",
			Category:    "host",
			Asset:       "/",
			Status:      StatusError,
			Severity:    "high",
			Message:     "Root filesystem usage could not be determined.",
			Description: "The auditor could not find root filesystem information in the collected disk inventory.",
			Recommendation: "Verify that the root filesystem is visible " +
				"to the auditor and review disk inventory collection.",
		})
		return
	}

	pct := root.UsedPercent

	evidence := map[string]any{
		"device":       root.Device,
		"mount":        root.Mount,
		"filesystem":   root.FSType,
		"size_gb":      root.SizeGB,
		"used_gb":      root.UsedGB,
		"free_gb":      root.FreeGB,
		"used_percent": root.UsedPercent,
	}

	switch {
	case pct >= 90:
		report.Add(Finding{
			ID:       "DISK001",
			Category: "host",
			Asset:    root.Mount,
			Status:   StatusCritical,
			Severity: "high",
			Message: fmt.Sprintf(
				"Root filesystem usage is %d%% (%d GB used of %d GB).",
				pct, root.UsedGB, root.SizeGB,
			),
			Description:    "Root filesystem utilization has reached the critical threshold of 90%.",
			Recommendation: "Investigate large files, application logs, and unused container resources before deleting data.",
			Evidence:       evidence,
		})

	case pct >= 80:
		report.Add(Finding{
			ID:       "DISK001",
			Category: "host",
			Asset:    root.Mount,
			Status:   StatusWarning,
			Severity: "medium",
			Message: fmt.Sprintf(
				"Root filesystem usage is %d%% (%d GB used of %d GB).",
				pct, root.UsedGB, root.SizeGB,
			),
			Description:    "Root filesystem utilization has reached the warning threshold of 80%.",
			Recommendation: "Review disk growth and plan cleanup or capacity expansion.",
			Evidence:       evidence,
		})

	default:
		report.Add(Finding{
			ID:          "DISK001",
			Category:    "host",
			Asset:       root.Mount,
			Status:      StatusPass,
			Severity:    "info",
			Message:     fmt.Sprintf("Root filesystem usage is %d%%.", pct),
			Description: "Root filesystem utilization is below the warning threshold.",
			Evidence:    evidence,
		})
	}
}

func checkMemory(report *Report) {
	vm, err := mem.VirtualMemory()
	if err != nil {
		report.Add(Finding{
			ID:          "MEM001",
			Category:    "host",
			Asset:       "system memory",
			Status:      StatusError,
			Severity:    "medium",
			Message:     "Unable to read memory utilization: " + err.Error(),
			Description: "The auditor could not retrieve system memory statistics.",
			Recommendation: "Check access to system memory statistics " +
				"and verify that gopsutil supports this environment.",
		})
		return
	}

	checkMemoryUsage(report, vm)
}

func checkMemoryUsage(report *Report, vm *mem.VirtualMemoryStat) {
	pct := vm.UsedPercent

	evidence := map[string]any{
		"total_bytes":     vm.Total,
		"used_bytes":      vm.Used,
		"available_bytes": vm.Available,
		"free_bytes":      vm.Free,
		"used_percent":    vm.UsedPercent,
	}

	switch {
	case pct >= 95:
		report.Add(Finding{
			ID:          "MEM001",
			Category:    "host",
			Asset:       "system memory",
			Status:      StatusCritical,
			Severity:    "high",
			Message:     fmt.Sprintf("Memory utilization is %.1f%%.", pct),
			Description: "System memory utilization has reached the critical threshold of 95%.",
			Recommendation: "Identify memory-intensive processes and " +
				"check for memory leaks or insufficient capacity.",
			Evidence: evidence,
		})

	case pct >= 85:
		report.Add(Finding{
			ID:          "MEM001",
			Category:    "host",
			Asset:       "system memory",
			Status:      StatusWarning,
			Severity:    "medium",
			Message:     fmt.Sprintf("Memory utilization is %.1f%%.", pct),
			Description: "System memory utilization has reached the warning threshold of 85%.",
			Recommendation: "Review process memory usage and monitor " +
				"memory pressure.",
			Evidence: evidence,
		})

	default:
		report.Add(Finding{
			ID:          "MEM001",
			Category:    "host",
			Asset:       "system memory",
			Status:      StatusPass,
			Severity:    "info",
			Message:     fmt.Sprintf("Memory utilization is %.1f%%.", pct),
			Description: "System memory utilization is below the warning threshold.",
			Evidence:    evidence,
		})
	}
}

func checkServices(report *Report, inv *inventory.Inventory) {
	failedCount := 0

	for _, s := range inv.Services {
		if strings.EqualFold(s.State, "failed") ||
			strings.EqualFold(s.SubState, "failed") {

			failedCount++

			report.Add(Finding{
				ID:       "SVC001",
				Category: "service",
				Asset:    s.Name,
				Status:   StatusCritical,
				Severity: "high",
				Message: fmt.Sprintf(
					"Service %s is in a failed state (state=%s, substate=%s).",
					s.Name, s.State, s.SubState,
				),
				Description: "The service manager reports this service as failed. This may affect applications or system functionality that depend on it.",
				Recommendation: fmt.Sprintf(
					"Inspect the service with `systemctl status %s` and `journalctl -u %s`. Identify the root cause before restarting or changing the service.",
					s.Name, s.Name,
				),
				Evidence: map[string]any{
					"name":           s.Name,
					"description":    s.Description,
					"state":          s.State,
					"sub_state":      s.SubState,
					"enabled":        s.Enabled,
					"active_since":   s.ActiveSince,
					"main_pid":       s.MainPID,
					"memory_current": s.MemoryCurrent,
				},
			})
		}
	}

	if failedCount == 0 {
		report.Add(Finding{
			ID:          "SVC001",
			Category:    "service",
			Asset:       "system services",
			Status:      StatusPass,
			Severity:    "info",
			Message:     "No failed services were reported by inventory.",
			Description: "The collected service inventory did not report any services in a failed state.",
			Evidence: map[string]any{
				"checked_services": len(inv.Services),
				"failed_services":  0,
			},
		})
	}
}
