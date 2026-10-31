package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
	"github.com/spf13/cobra"
)

var inventorySummary bool

var inventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Collect complete system inventory",
	Long: `Collect the complete infrastructure inventory.

By default, this command prints the full JSON inventory.

Use --summary for a categorized human-readable report.

Examples:
  auditor inventory
  auditor inventory --summary
`,
	Run: func(cmd *cobra.Command, args []string) {
		inv, err := inventory.Collect()
		if err != nil {
			log.Fatal(err)
		}

		if inventorySummary {
			printInventorySummary(inv)
			return
		}

		// Preserve the existing default JSON output.
		b, err := json.MarshalIndent(inv, "", "  ")
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(string(b))
	},
}

func init() {
	inventoryCmd.Flags().BoolVar(
		&inventorySummary,
		"summary",
		false,
		"Show categorized inventory summary",
	)

	rootCmd.AddCommand(inventoryCmd)
}

func printInventorySummary(inv *inventory.Inventory) {
	var healthy []string
	var attention []string
	var highRisk []string

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("       CLOUDBUSKET INVENTORY SUMMARY")
	fmt.Println("========================================")

	fmt.Printf("Hostname : %s\n", inv.Hostname)
	fmt.Printf("OS       : %s %s\n", inv.OS.Platform, inv.OS.Version)
	fmt.Printf("CPU      : %s (%d cores)\n", inv.CPU.Model, inv.CPU.Cores)
	fmt.Printf("Memory   : %d GB total\n", inv.Memory.TotalGB)

	if inv.Cloud.Provider != "" {
		fmt.Printf("Cloud    : %s\n", inv.Cloud.Provider)
	}

	fmt.Printf("Disks    : %d\n", len(inv.Disk))
	fmt.Printf("Ports    : %d\n", len(inv.Ports))
	fmt.Printf("Services : %d\n", len(inv.Services))

	// Disk capacity checks.
	for _, disk := range inv.Disk {
		if !includeSummaryDisk(disk) {
			continue
		}
		message := fmt.Sprintf(
			"Disk %s (%s): %d%% used, %d GB free",
			disk.Mount,
			disk.Device,
			disk.UsedPercent,
			disk.FreeGB,
		)

		switch {
		case disk.UsedPercent >= 95:
			highRisk = append(highRisk, message)

		case disk.UsedPercent >= 80:
			attention = append(attention, message)

		default:
			healthy = append(healthy, message)
		}
	}

	// Port exposure checks.
	sshReported := false
	for _, port := range inv.Ports {
		endpoint := fmt.Sprintf(
			"%s %s:%d (%s)",
			port.Protocol,
			port.Address,
			port.Port,
			port.ProcessName,
		)

		if port.BindScope == "loopback" {
			healthy = append(
				healthy,
				endpoint+" - restricted to localhost",
			)
			continue
		}

		if port.BindScope != "all_interfaces" &&
			port.BindScope != "public_address" {
			continue
		}

		if port.Protocol == "tcp" && isSensitivePort(port.Port) {
			highRisk = append(
				highRisk,
				endpoint+" - sensitive service bound to all interfaces; verify firewall restrictions",
			)
			continue
		}

		if port.Protocol == "tcp" && port.Port == 22 {
			if !sshReported {
				attention = append(
					attention,
					"SSH is bound to all interfaces (IPv4/IPv6 entries may both exist); verify cloud firewall and access restrictions",
				)
				sshReported = true
			}
			continue
		}

		if port.Protocol == "tcp" &&
			(port.Port == 80 || port.Port == 443) {
			healthy = append(
				healthy,
				endpoint+" - web listener; verify intended public access",
			)
			continue
		}

		if port.Protocol == "tcp" {
			attention = append(
				attention,
				endpoint+" - TCP listener on all interfaces; identify and verify exposure",
			)
		}
	}

	if inv.PortCollectionError != "" {
		attention = append(
			attention,
			"Port collection incomplete: "+inv.PortCollectionError,
		)
	}

	printSummarySection("HIGH RISK", highRisk)
	printSummarySection("NEEDS ATTENTION", attention)
	printSummarySection("HEALTHY", healthy)

	fmt.Println("========================================")
	fmt.Println("Note: Bind address does not prove internet")
	fmt.Println("reachability. Verify host and cloud firewalls.")
	fmt.Println("========================================")
	fmt.Println()
}

func isSensitivePort(port uint32) bool {
	switch port {
	case 1433, 1521, 2375, 2376,
		27017, 27018, 3306, 5432,
		6379, 9200, 11211, 11434:
		return true
	default:
		return false
	}
}

func printSummarySection(title string, items []string) {
	fmt.Printf("\n--- %s (%d) ---\n", title, len(items))

	if len(items) == 0 {
		fmt.Println("None")
		return
	}

	for _, item := range items {
		fmt.Printf("  • %s\n", item)
	}
}
func includeSummaryDisk(disk inventory.DiskInfo) bool {
	// Ignore loop devices used by temporary/container workloads.
	if strings.HasPrefix(disk.Device, "/dev/loop") {
		return false
	}

	// Ignore virtual and pseudo filesystems.
	switch disk.FSType {
	case "proc", "sysfs", "tmpfs", "devtmpfs", "devpts",
		"overlay", "cgroup", "cgroup2", "squashfs",
		"tracefs", "securityfs", "pstore", "configfs",
		"debugfs", "mqueue", "hugetlbfs", "fusectl",
		"ramfs", "efivarfs", "bpf", "nsfs",
		"binfmt_misc":
		return false
	}

	return true
}
