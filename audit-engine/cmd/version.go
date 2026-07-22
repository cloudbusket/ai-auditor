package cmd

import (
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version information",
	Long:  "Display the current version of CloudBusket AI Infrastructure Auditor.",

	Run: func(cmd *cobra.Command, args []string) {
		version.Print()
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
