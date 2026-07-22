package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/health"
	"github.com/spf13/cobra"
)

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Perform health check",
	Long:  "Verify that the auditor binary is functioning correctly.",

	Run: func(cmd *cobra.Command, args []string) {

		result := health.Check()

		b, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println(string(b))
	},
}

func init() {
	rootCmd.AddCommand(healthCmd)
}
