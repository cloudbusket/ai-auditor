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
			ID:       "DISK001",
			Category: "host",
			Status:   StatusError,
			Severity: "high",
			Message:  "Root filesystem usage could not be determined.",
			Recommendation: "Verify that the root filesystem is visible " +
				"to the auditor and review disk inventory collection.",
		})
		return
	}

	pct := root.UsedPercent

	switch {
	case pct >= 90:
		report.Add(Finding{
			ID:       "DISK001",
			Category: "host",
			Status:   StatusCritical,
			Severity: "high",
			Message: fmt.Sprintf(
				"Root filesystem usage is %d%% (%d GB used of %d GB).",
				pct, root.UsedGB, root.SizeGB,
			),
			Recommendation: "Investigate large files, application logs, " +
				"and unused container resources before deleting data.",
		})
	case pct >= 80:
		report.Add(Finding{
			ID:       "DISK001",
			Category: "host",
			Status:   StatusWarning,
			Severity: "medium",
			Message: fmt.Sprintf(
				"Root filesystem usage is %d%% (%d GB used of %d GB).",
				pct, root.UsedGB, root.SizeGB,
			),
			Recommendation: "Review disk growth and plan cleanup or " +
				"capacity expansion.",
		})
	default:
		report.Add(Finding{
			ID:       "DISK001",
			Category: "host",
			Status:   StatusPass,
			Severity: "info",
			Message:  fmt.Sprintf("Root filesystem usage is %d%%.", pct),
		})
	}
}

func checkMemory(report *Report) {
	vm, err := mem.VirtualMemory()
	if err != nil {
		report.Add(Finding{
			ID:       "MEM001",
			Category: "host",
			Status:   StatusError,
			Severity: "medium",
			Message:  "Unable to read memory utilization: " + err.Error(),
			Recommendation: "Check access to system memory statistics " +
				"and verify that gopsutil supports this environment.",
		})
		return
	}

	pct := vm.UsedPercent

	switch {
	case pct >= 95:
		report.Add(Finding{
			ID:       "MEM001",
			Category: "host",
			Status:   StatusCritical,
			Severity: "high",
			Message:  fmt.Sprintf("Memory utilization is %.1f%%.", pct),
			Recommendation: "Identify memory-intensive processes and " +
				"check for memory leaks or insufficient capacity.",
		})
	case pct >= 85:
		report.Add(Finding{
			ID:       "MEM001",
			Category: "host",
			Status:   StatusWarning,
			Severity: "medium",
			Message:  fmt.Sprintf("Memory utilization is %.1f%%.", pct),
			Recommendation: "Review process memory usage and monitor " +
				"memory pressure.",
		})
	default:
		report.Add(Finding{
			ID:       "MEM001",
			Category: "host",
			Status:   StatusPass,
			Severity: "info",
			Message:  fmt.Sprintf("Memory utilization is %.1f%%.", pct),
		})
	}
}

func checkServices(report *Report, inv *inventory.Inventory) {
	failed := 0

	for _, service := range inv.Services {
		if strings.EqualFold(service.State, "failed") ||
			strings.EqualFold(service.SubState, "failed") {
			failed++

			report.Add(Finding{
				ID:       "SVC001",
				Category: "service",
				Status:   StatusCritical,
				Severity: "high",
				Message: fmt.Sprintf(
					"Service %q is reported as failed (state=%s, substate=%s).",
					service.Name, service.State, service.SubState,
				),
				Recommendation: "Inspect the service with systemctl status " +
					service.Name + " and review its journal logs.",
			})
		}
	}

	if failed == 0 {
		report.Add(Finding{
			ID:       "SVC001",
			Category: "service",
			Status:   StatusPass,
			Severity: "info",
			Message:  "No failed services were reported by inventory.",
		})
	}
}
