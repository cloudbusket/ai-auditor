package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run infrastructure audit scan",
	Long: `Run infrastructure security, compliance and configuration
checks against the current system.

The scan engine will be implemented in the next development phase.`,

	Run: func(cmd *cobra.Command, args []string) {

		fmt.Println("CloudBusket AI Auditor")
		fmt.Println("----------------------")
		fmt.Println("Infrastructure scanning is not implemented yet.")
		fmt.Println("Coming in v0.2.0")

	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
