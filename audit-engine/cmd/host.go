package cmd

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
	"github.com/spf13/cobra"
)

var hostCmd = &cobra.Command{
	Use:   "host",
	Short: "Collect host inventory",
	Run: func(cmd *cobra.Command, args []string) {

		info, err := inventory.Collect()
		if err != nil {
			log.Fatal(err)
		}

		host := struct {
			Hostname       string                   `json:"hostname"`
			OS             inventory.OSInfo         `json:"os"`
			Kernel         inventory.KernelInfo     `json:"kernel"`
			CPU            inventory.CPUInfo        `json:"cpu"`
			Memory         inventory.MemoryInfo     `json:"memory"`
			Disk           []inventory.DiskInfo     `json:"disk,omitempty"`
			Network        []inventory.NetworkInfo  `json:"network,omitempty"`
			Virtualization inventory.Virtualization `json:"virtualization,omitempty"`
			Services       []inventory.ServiceInfo  `json:"services"`
		}{
			Hostname:       info.Hostname,
			OS:             info.OS,
			Kernel:         info.Kernel,
			CPU:            info.CPU,
			Memory:         info.Memory,
			Disk:           info.Disk,
			Network:        info.Network,
			Virtualization: info.Virtualization,
			Services:       info.Services,
		}

		b, _ := json.MarshalIndent(host, "", "  ")
		fmt.Println(string(b))
	},
}

func init() {
	rootCmd.AddCommand(hostCmd)
}
