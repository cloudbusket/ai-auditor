package cmd

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
	"github.com/spf13/cobra"
)

var inventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Collect complete system inventory",
	Long: `Collect the complete infrastructure inventory.

This command combines all available collectors:

  • Host
  • Cloud
  • Operating System
  • CPU
  • Memory
  • Kernel
  • Disk
  • Network
  • Virtualization
  • Docker
  • (Kubernetes - when available)

Examples:

  auditor inventory
  auditor inventory --pretty
  auditor inventory --output json
`,

	Run: func(cmd *cobra.Command, args []string) {

		inv, err := inventory.Collect()
		if err != nil {
			log.Fatal(err)
		}

		b, err := json.MarshalIndent(inv, "", "  ")
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(string(b))
	},
}

func init() {
	rootCmd.AddCommand(inventoryCmd)
}
