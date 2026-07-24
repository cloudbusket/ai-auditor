package cmd

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/docker"
	"github.com/spf13/cobra"
)

var dockerCmd = &cobra.Command{
	Use:   "docker",
	Short: "Collect Docker inventory",
	Run: func(cmd *cobra.Command, args []string) {

		info, err := docker.Collect()
		if err != nil {
			log.Fatal(err)
		}

		b, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(b))
	},
}

func init() {
	rootCmd.AddCommand(dockerCmd)
}
