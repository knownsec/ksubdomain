package core

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

//SrcIp     string           = "10.13.20.60"
//device    string           = "en0"
//SrcMac    net.HardwareAddr = net.HardwareAddr{0xf0, 0x18, 0x98, 0x1a, 0x56, 0xe8}
//DstMac    net.HardwareAddr = net.HardwareAddr{0x5c, 0xc9, 0x99, 0x33, 0x34, 0x80

func GetDevices(defaultSelect int) EthTable {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	data := make(map[string]net.IP)
	keys := []string{}

	for _, d := range devices {
		for _, address := range d.Addresses {
			ip := address.IP
			if ip.To4() != nil && !ip.IsLoopback() {
				fmt.Printf("\n[%d] Name: %s\n", len(keys), d.Name)
				fmt.Println("Description: ", d.Description)
				fmt.Println("Devices addresses: ", d.Description)
				fmt.Println("IP address: ", ip)
				fmt.Println("Subnet mask: ", address.Netmask)
				data[d.Name] = ip
				keys = append(keys, d.Name)
			}
		}
	}
	if len(keys) == 0 {
		panic("获取不到可用的设备名称")
	} else if len(keys) == 1 {
		defaultSelect = 0
	}
	if defaultSelect == -1 {
		var i int
		fmt.Println("选择一个可用网卡ID:")
		input, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			panic("There were errors reading, exiting program.")
		}
		i, err2 := strconv.Atoi(strings.TrimSpace(input))
		if err2 != nil {
			panic("There were errors reading, exiting program.")
		}

		if i < 0 || i >= len(keys) {
			panic("ID超出了范围")
		}
		defaultSelect = i
	}
	deviceName := keys[defaultSelect]
	ip := data[deviceName]
	fmt.Println("Use Device:", deviceName)
	fmt.Println("Use IP:", ip)
	c := GetGateMacAddress(deviceName)
	fmt.Println("Local Mac:", c[1])
	fmt.Println("GateWay Mac:", c[0])
	fmt.Println("")
	return EthTable{ip, deviceName, c[1], c[0]}
}

func GetGateMacAddress(dvice string) [2]net.HardwareAddr {
	// 获取网关mac地址
	domain := RandomStr(4) + "paper.seebug.org"
	_signal := make(chan [2]net.HardwareAddr)
	go func(device string, domain string, signal chan [2]net.HardwareAddr) {
		var (
			snapshot_len int32         = 1024
			promiscuous  bool          = false
			timeout      time.Duration = -1 * time.Second
			handle       *pcap.Handle
		)
		var err error
		handle, err = pcap.OpenLive(
			device,
			snapshot_len,
			promiscuous,
			timeout,
		)
		if err != nil {
			panic(err)
		}
		defer handle.Close()
		// Use the handle as a packet source to process all packets
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			packet, err := packetSource.NextPacket()
			fmt.Print(".")
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
							srcMac := eth.SrcMAC
							dstMac := eth.DstMAC

							signal <- [2]net.HardwareAddr{srcMac, dstMac}
							// 网关mac 和 本地mac
							return
						}
					}
				}
			}

		}
	}(dvice, domain, _signal)
	var c [2]net.HardwareAddr
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

	fmt.Print("\n")
	return c
}
