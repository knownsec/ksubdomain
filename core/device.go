package core

import (
	"bufio"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"ksubdomain/gologger"
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

func GetDevices(options *Options) EthTable {
	// Find all devices
	defaultSelect := options.NetworkId
	devices, err := pcap.FindAllDevs()
	if err != nil {
		gologger.Fatalf("获取网络设备失败:%s\n", err.Error())
	}
	data := make(map[string]net.IP)
	keys := []string{}

	for _, d := range devices {
		for _, address := range d.Addresses {
			ip := address.IP
			if ip.To4() != nil && !ip.IsLoopback() {
				gologger.Printf("  [%d] Name: %s\n", len(keys), d.Name)
				gologger.Printf("  Description: %s\n", d.Description)
				gologger.Printf("  Devices addresses: %s\n", d.Description)
				gologger.Printf("  IP address: %s\n", ip)
				gologger.Printf("  Subnet mask: %s\n\n", address.Netmask.String())
				data[d.Name] = ip
				keys = append(keys, d.Name)
			}
		}
	}
	if len(keys) == 0 {
		gologger.Fatalf("获取不到可用的设备名称\n")
	} else if len(keys) == 1 {
		defaultSelect = 0
	}
	if defaultSelect == -1 {
		var i int
		if options.Silent {
			gologger.Fatalf("slient模式下需要指定-e参数\n")
		}
		gologger.Infof("选择一个可用网卡ID:")
		input, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		i, err2 := strconv.Atoi(strings.TrimSpace(input))
		if err2 != nil {
			gologger.Fatalf("读入ID失败，确认输入的是数字?\n")
		}

		if i < 0 || i >= len(keys) {
			gologger.Fatalf("ID超出了范围\n")
		}
		defaultSelect = i
	}
	deviceName := keys[defaultSelect]
	ip := data[deviceName]
	gologger.Infof("Use Device: %s\n", deviceName)
	gologger.Infof("Use IP:%s\n", ip.String())
	c := GetGateMacAddress(deviceName)
	gologger.Infof("Local Mac:%s\n", c[1])
	gologger.Infof("GateWay Mac:%s\n", c[0])
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
			gologger.Printf(".")
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
			gologger.Printf("\n")
			goto END
		default:
			_, _ = net.LookupHost(domain)
			time.Sleep(time.Millisecond * 10)
		}
	}
END:
	return c
}
