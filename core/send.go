package core

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"
)

type SendDog struct {
	ether          EthTable
	dns            []string
	handle         *pcap.Handle
	index          uint32
	lock           *sync.RWMutex
	increate_index bool // 是否使用index自增
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
	d.index = 10000
	d.increate_index = true
	d.lock = &sync.RWMutex{}
	//defer d.handle.Close()
}
func (d *SendDog) Lock() {
	d.lock.Lock()
}
func (d *SendDog) UnLock() {
	d.lock.Unlock()
}
func (d *SendDog) ChoseDns() string {
	if RecvIndex <= 1200 {
		return d.dns[rand.Intn(len(d.dns)-1)]
	} else {
		max := 0
		dnsname := ""
		DnsChoice.Range(func(k, v interface{}) bool {
			vv := v.(int)
			if vv > max {
				max = vv
				dnsname = k.(string)
			}
			return true
		})
		return dnsname
	}
}
func (d *SendDog) BuildStatusTable(domain string, dns string) uint16 {
	// 生成本地状态表，返回ID和SrcPort参数
	d.lock.Lock()
	defer d.lock.Unlock()
	if d.index >= 60000 {
		d.increate_index = false
	}
	if d.increate_index {
		d.index++
	} else {
		for {
			v, error := LocalStack.Pop()
			if error == nil {
				d.index = v
				break
			} else {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
	for {
		if _, ok := LocalStauts.Load(d.index); !ok {
			LocalStauts.Store(d.index, StatusTable{Domain: domain, Dns: dns, Time: time.Now().Unix(), Retry: 0})
			break
		}
		d.index++
	}
	return uint16(d.index)
}

func (d *SendDog) Send(domain string, dnsname string, srcport uint16) {
	DstIp := net.ParseIP(dnsname).To4()
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
		FragOffset: 0,
		TTL:        255,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      d.ether.SrcIp,
		DstIP:      DstIp,
	}
	// Our UDP header
	udp := &layers.UDP{
		//SrcPort: layers.UDPPort(RandInt64(10000, 50000)),
		SrcPort: layers.UDPPort(srcport),
		DstPort: layers.UDPPort(53),
	}
	// Our DNS header
	dns := &layers.DNS{
		ID:      404,
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
