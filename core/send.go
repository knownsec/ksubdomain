package core

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
)

type SendDog struct {
	ether  EthTable
	dns    []string
	handle *pcap.Handle
}

func (d *SendDog) Init(ether EthTable, dns []string) {
	d.ether = ether
	d.dns = dns
	var (
		snapshot_len int32 = 1024
		promiscuous  bool  = false
		err          error
		timeout      time.Duration = -1 * time.Second
	)
	d.handle, err = pcap.OpenLive(d.ether.Device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	//defer d.handle.Close()
}
func (d *SendDog) ChoseDns() string {
	return d.dns[0]
}
func (d *SendDog) Send(domain string) {
	DstIp := net.ParseIP(d.ChoseDns()).To4()
	eth := &layers.Ethernet{
		SrcMAC:       d.ether.SrcMac,
		DstMAC:       d.ether.DstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	// Our IPv4 header
	ip := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     0, // FIX
		Id:         0,
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,   //16384,
		TTL:        128, //64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      d.ether.SrcIp,
		DstIP:      DstIp,
	}
	// Our UDP header
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(RandInt64(10000, 50000)),
		DstPort: layers.UDPPort(53),
	}
	// Our DNS header
	dns := &layers.DNS{
		ID:      111,
		QDCount: 1,
		RD:      false, //递归查询标识
	}
	dns.Questions = append(dns.Questions,
		layers.DNSQuestion{
			Name:  []byte(domain),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		})
	// Our UDP header
	_ = udp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{
			ComputeChecksums: true, // automatically compute checksums
			FixLengths:       true,
		},
		eth, ip, udp, dns,
	)
	if err != nil {
		log.Fatal(err)
	}
	err = d.handle.WritePacketData(buf.Bytes())
	if err != nil {
		fmt.Println(err)
	}
}
func (d *SendDog) Close() {
	d.handle.Close()
}
