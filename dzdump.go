package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"strconv"
	"time"
)

var (
	device       string
	snapshot_len int32         = 65535
	promiscuous  bool          = false
	timeout      time.Duration = -1 * time.Second
	err          error
	handle       *pcap.Handle
	filter       string
)

func init() {
	flag.StringVar(&device, "i", "lo0", "Device name,default lo0")
	flag.StringVar(&filter, "X", "", "Filter")
	flag.Parse()
}
func main() {
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	if filter != "" {
		fmt.Println(filter)
		err = handle.SetBPFFilter(filter)
		//err = handle.SetBPFFilter("dst port 8080")
		if err != nil {
			log.Fatal(err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// get IPV4(net layer)
		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ipv4Layer == nil {
			log.Println("can not found ipv4 packets.")
			continue
		}

		ip, _ := ipv4Layer.(*layers.IPv4)
		// get TCP
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("[TCP] %s [%d] ---> %s [%d], Seq: %d, Ack: %d, "+
				"Flags:FIN[%s] SYN[%s] RST[%s] PSH[%s] ACK[%s] URG[%s] ECE[%s] CWR[%s] NS[%s], Window: %d\n",
				ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, tcp.Seq, tcp.Ack,
				strconv.FormatBool(tcp.FIN), strconv.FormatBool(tcp.SYN), strconv.FormatBool(tcp.RST), strconv.FormatBool(tcp.PSH),
				strconv.FormatBool(tcp.ACK), strconv.FormatBool(tcp.URG), strconv.FormatBool(tcp.ECE), strconv.FormatBool(tcp.CWR),
				strconv.FormatBool(tcp.NS), tcp.Window)
			fmt.Printf("Payload: %s\n", string(tcp.Payload))
			fmt.Println()
		}

		// get UDP
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			fmt.Printf("[UDP] %s [%d] ---> %s [%d], Length: %d\n", ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort, udp.Length)
			fmt.Printf("Payload: %s\n", string(udp.Payload))
			fmt.Println()
		}
	}
}
