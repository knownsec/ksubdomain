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

//SrcIp     string           = "10.13.20.60"
//device    string           = "en0"
//SrcMac    net.HardwareAddr = net.HardwareAddr{0xf0, 0x18, 0x98, 0x1a, 0x56, 0xe8}
//DstMac    net.HardwareAddr = net.HardwareAddr{0x5c, 0xc9, 0x99, 0x33, 0x34, 0x80

func GetDevices() EthTable {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("fail to get net interfaces: %v", err)
	}

	for _, netInterface := range netInterfaces {
		interfaceName := netInterface.Name
		inter, err := net.InterfaceByName(interfaceName)
		if err != nil {
			log.Fatalf("无法获取信息: %v", err)
		}

		addrs, err := inter.Addrs()

		if err != nil {
			log.Fatalln(err)
		}
		// 获取IP地址，子网掩码
		for _, addr := range addrs {
			if ip, ok := addr.(*net.IPNet); ok && !ip.IP.IsLoopback() {
				if ip.IP.To4() != nil {
					fmt.Println("Name:",interfaceName)
					fmt.Println("IP:", ip.IP)
					fmt.Println("Mask:", ip.Mask)
					fmt.Println("Mac:", inter.HardwareAddr.String())
					c := GetGateMacAddress(interfaceName)
					fmt.Println("GateWay Mac:",c)
					return EthTable{ip.IP, interfaceName, inter.HardwareAddr, c}
				}
			}
		}
	}
	panic("获取不到可用的IP或网关搜索失败")
}

func GetGateMacAddress(dvice string) net.HardwareAddr{
	// 获取网关mac地址
	domain := RandomStr(4) + "paper.seebug.org"
	_signal := make(chan net.HardwareAddr)
	go func(device string, domain string, signal chan net.HardwareAddr) {
		var (
			snapshot_len int32         = 1024
			promiscuous  bool          = false
			timeout      time.Duration = -1 * time.Second
			handle       *pcap.Handle
		)
		handle, _ = pcap.OpenLive(
			device,
			snapshot_len,
			promiscuous,
			timeout,
		)
		defer handle.Close()
		// Use the handle as a packet source to process all packets
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			packet, err := packetSource.NextPacket()
			fmt.Print("1111")
			if err != nil {
				continue
			}
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)
				if !dns.QR {
					continue
				}
				for _, v := range dns.Questions {
					if string(v.Name) == domain {
						ethLayer := packet.Layer(layers.LayerTypeEthernet)
						if ethLayer != nil {
							eth := ethLayer.(*layers.Ethernet)
							signal <- eth.SrcMAC
							return
						}
					}
				}
			}

		}
	}(dvice, domain, _signal)
	var c net.HardwareAddr
	for {
		select {
		case c = <-_signal:
			goto END
		default:
			_, _ = net.LookupHost(domain)
			time.Sleep(time.Millisecond * 10)
		}
	}
	END:
		return c
}