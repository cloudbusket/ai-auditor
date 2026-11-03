package cmd

import (
	"fmt"
	"os"

	appversion "github.com/cloudbusket/ai-auditor/audit-engine/internal/version"
	"github.com/spf13/cobra"
)

const appDescription = "Infrastructure intelligence, health assessment and security auditing."

var rootCmd = &cobra.Command{
	Use:   "auditor",
	Short: appversion.AppName,
	Long: `CloudBusket AI Auditor

Infrastructure intelligence, health assessment and security auditing.

Inspect Linux systems, cloud environments, Docker workloads, network
services and security configurations from one command-line interface.

The auditor collects infrastructure inventory, evaluates system health,
identifies potential risks and generates structured audit information.

Documentation: https://cloudbusket.com
`,
	Version:       appversion.Version,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.SetHelpCommand(&cobra.Command{
		Use:    "help [command]",
		Short:  "Help about any command",
		Hidden: false,
	})

	rootCmd.SetVersionTemplate(`{{with .Name}}{{printf "%s\n" .}}{{end}}Version: {{.Version}}
`)

	rootCmd.SetUsageTemplate(`Usage:
  {{.UseLine}}

{{if .HasAvailableSubCommands}}Available Commands:
{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}  {{rpad .Name .NamePadding }} {{.Short}}
{{end}}{{end}}{{end}}
{{if .HasAvailableLocalFlags}}Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
{{end}}
{{if .HasAvailableInheritedFlags}}Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}
{{end}}
Use "{{.CommandPath}} [command] --help" for more information about a command.
`)
}
