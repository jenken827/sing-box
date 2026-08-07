//go:build !with_netbird

package main

import "github.com/spf13/cobra"

var commandNetbirdRun = &cobra.Command{
	Use:   "netbird-run",
	Short: "Run netbird engine (not available - compile with -tags with_netbird)",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var commandNetbirdStatus = &cobra.Command{
	Use:   "netbird-status",
	Short: "Show netbird engine status (not available - compile with -tags with_netbird)",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	mainCommand.AddCommand(commandNetbirdRun)
	mainCommand.AddCommand(commandNetbirdStatus)
}
