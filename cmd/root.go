/*
Copyright © 2022 Sivaram Sajeev <sivaramsajeev@gmail.com>

*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "knocker",
	Short: "Network Analyzer",
	Long:  `Do basic port scan, sniffing & Have some FUN`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
