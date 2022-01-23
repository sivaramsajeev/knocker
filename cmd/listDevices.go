/*
Copyright © 2022 Sivaram Sajeev <sivaramsajeev@gmail.com>

*/
package cmd

import (
	"fmt"

	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
	"log"
	"strings"
)

var listDevicesCmd = &cobra.Command{
	Use:   "listDevices",
	Short: "List all the available devices in the system",
	Long:  `Identify the required device before you initiate a port scan or sniffer`,
	Run: func(cmd *cobra.Command, args []string) {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Panicln(err)
		}
		for _, device := range devices {
			fmt.Printf("\n%s\n%s\n", device.Name, strings.Repeat("-", 30))
			for _, address := range device.Addresses {
				fmt.Printf(" IP: %s\n", address.IP)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(listDevicesCmd)
}
