//go:build !with_netbird

package main

import (
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spf13/cobra"
)

var commandRunAll = &cobra.Command{
	Use:   "run-all",
	Short: "Run sing-box and netbird (not available - compile with -tags with_netbird)",
	Run: func(cmd *cobra.Command, args []string) {
		log.Fatal(E.New("netbird integration not enabled, compile with -tags with_netbird"))
	},
}

func init() {
	mainCommand.AddCommand(commandRunAll)
}
