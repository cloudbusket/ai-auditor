package cmd

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
	"github.com/spf13/cobra"
)

var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Collect cloud metadata",
	Run: func(cmd *cobra.Command, args []string) {

		info, err := inventory.Collect()
		if err != nil {
			log.Fatal(err)
		}

		b, _ := json.MarshalIndent(info.Cloud, "", "  ")
		fmt.Println(string(b))
	},
}

func init() {
	rootCmd.AddCommand(cloudCmd)
}
