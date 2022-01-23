/*
Copyright © 2022 Sivaram Sajeev <sivaramsajeev@gmail.com>

*/
package cmd

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
	"log"
	"bytes"
)

var startSnifferCmd = &cobra.Command{
	Use:   "startSniffer",
	Short: "Sniffing on a compromised network",
	Run: func(cmd *cobra.Command, args []string) {
		device, _ := cmd.Flags().GetString("device")
		word, _ := cmd.Flags().GetString("word")

		handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
		if err != nil {
			log.Panicln(err)
		}
		defer handle.Close()
		if err := handle.SetBPFFilter("tcp and dst port 443 or dst port 80"); err != nil {
			log.Panicln(err)
		}

		source := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range source.Packets() {
			appLayer := packet.ApplicationLayer()
			if appLayer == nil {
				continue
			}
			payload := appLayer.Payload()
			if bytes.Contains(payload, []byte(word)) {
				fmt.Print(string(payload))
			}
		}

	},
}

func init() {
	rootCmd.AddCommand(startSnifferCmd)
	startSnifferCmd.Flags().StringP("device", "d", "eth0", "Device for sniffing")
	startSnifferCmd.MarkFlagRequired("device")

	startSnifferCmd.Flags().StringP("word", "w", "Host", "Word to look for eg, -w Host")
	startSnifferCmd.MarkFlagRequired("word")
}
