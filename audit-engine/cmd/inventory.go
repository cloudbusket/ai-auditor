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
	Short: "Collect host inventory",
	Long: `Collect detailed host inventory including:

• Operating System
• CPU
• Memory
• Kernel
• Hostname

The inventory is returned as formatted JSON.`,

	Run: func(cmd *cobra.Command, args []string) {

		info, err := inventory.Collect()
		if err != nil {
			log.Fatal(err)
		}

		b, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(string(b))
	},
}

func init() {
	rootCmd.AddCommand(inventoryCmd)
}
