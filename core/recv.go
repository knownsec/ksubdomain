package core

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"strconv"
	"time"
)

func Recv(device string) {
	var (
		snapshot_len int32         = 1024
		promiscuous  bool          = false
		timeout      time.Duration = -1 * time.Second
		handle       *pcap.Handle
	)
	handle, _ = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	err := handle.SetBPFFilter("udp port 53")
	if err != nil {
		log.Fatal(err)
	}
	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	defer handle.Close()
	index := 0
	//handle.SetBPFFilter()
	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			continue
		}
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)
			if !dns.QR {
				continue
			}
			if dns.ID == 111 {
				index += 1
				fmt.Print("\r recv:" + strconv.Itoa(index))
			}
			if dns.ID == 111 && dns.ANCount > 0 {
				msg := ""
				for _, v := range dns.Questions {
					msg += string(v.Name) + " => "
				}
				for _, v := range dns.Answers {
					msg += v.String() + " ttl:" + strconv.Itoa(int(v.TTL))
				}
				fmt.Print("\r", msg, "\n")
			}
		}
	}
}
