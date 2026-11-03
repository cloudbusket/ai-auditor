package cmd

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/dashboard"
	"github.com/spf13/cobra"
)

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Start the authenticated web dashboard",
	Long:  "Start the CloudBusket AI Auditor browser dashboard.",

	RunE: func(cmd *cobra.Command, args []string) error {
		password := os.Getenv("AUDITOR_DASHBOARD_PASSWORD")

		if strings.TrimSpace(password) == "" {
			return fmt.Errorf(
				"AUDITOR_DASHBOARD_PASSWORD is required",
			)
		}

		if len(password) < 16 {
			return fmt.Errorf(
				"dashboard password must contain at least 16 characters",
			)
		}

		handler, err := dashboard.NewHandler(password)
		if err != nil {
			return fmt.Errorf("dashboard initialization failed: %w", err)
		}

		address := "127.0.0.1:8088"

		server := &http.Server{
			Addr:              address,
			Handler:           handler,
			ReadHeaderTimeout: 10 * 1000000000,
			IdleTimeout:       60 * 1000000000,
		}

		fmt.Println("CloudBusket AI Auditor Dashboard")
		fmt.Println("Address: http://" + address)
		fmt.Println("Username: auditor")
		fmt.Println("Press Ctrl+C to stop.")

		if err := server.ListenAndServe(); err != nil &&
			err != http.ErrServerClosed {
			return fmt.Errorf("dashboard server failed: %w", err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(dashboardCmd)
}
