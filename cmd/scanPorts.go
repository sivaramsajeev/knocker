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
	"net"
	"strings"
	"time"
)

var (
	snaplen   = int32(320)
	promisc   = true
	timeout   = pcap.BlockForever
	filter    = "tcp[13] == 0x11 or tcp[13] == 0x10 or tcp[13] == 0x18"
	openPorts []string
)

var scanPortsCmd = &cobra.Command{
	Use:   "scanPorts",
	Short: "Scan ports on remote host",
	Run: func(cmd *cobra.Command, args []string) {
		ports, _ := cmd.Flags().GetString("ports")
		target, _ := cmd.Flags().GetString("target")
		device, _ := cmd.Flags().GetString("device")
		fmt.Printf("Scanning %s:%s on device %s\n", target, ports, device)

		go capture(device, target)
		time.Sleep(1 * time.Second)

		for _, port := range strings.Split(ports, ",") {
			target := fmt.Sprintf("%s:%s", target, port)
			c, err := net.DialTimeout("tcp", target, 1000*time.Millisecond)
			if err != nil {
				fmt.Println("Error capturing", err.Error())
				continue
			}
			c.Close()
		}
		time.Sleep(2 * time.Second)
		fmt.Println("Open ports ->", openPorts)
	},
}

func capture(iface, target string) {
	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
	if err != nil {
		log.Panicln(err)
	}
	defer handle.Close()
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Panicln(err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("Starting packet capture....")
	for packet := range source.Packets() {
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}
		transportLayer := packet.TransportLayer()
		if transportLayer == nil {
			continue
		}
		srcHost := networkLayer.NetworkFlow().Src().String()
		srcPort := transportLayer.TransportFlow().Src().String()
		if srcHost != target {
			continue
		}
		openPorts = append(openPorts, srcPort)
	}
}

func init() {
	rootCmd.AddCommand(scanPortsCmd)
	scanPortsCmd.Flags().StringP("ports", "p", "80", "Comma separated Ports to scan eg, -p 80,443")
	scanPortsCmd.MarkFlagRequired("ports")

	scanPortsCmd.Flags().StringP("target", "t", "127.0.0.1", "Target IP to scan")
	scanPortsCmd.MarkFlagRequired("target")

	scanPortsCmd.Flags().StringP("device", "d", "eth0", "Device to use")
	scanPortsCmd.MarkFlagRequired("device")
}
