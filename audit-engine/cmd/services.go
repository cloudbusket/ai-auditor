package cmd

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
	"github.com/spf13/cobra"
)

var servicesCmd = &cobra.Command{
	Use:   "services",
	Short: "Running system services",

	Run: func(cmd *cobra.Command, args []string) {

		inv, err := inventory.Collect()
		if err != nil {
			log.Fatal(err)
		}

		b, _ := json.MarshalIndent(inv.Services, "", "  ")

		fmt.Println(string(b))
	},
}

func init() {
	rootCmd.AddCommand(servicesCmd)
}
