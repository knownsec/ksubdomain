package core

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"ksubdomain/gologger"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type SendDog struct {
	ether          EthTable
	dns            []string
	handle         *pcap.Handle
	index          uint16
	lock           *sync.RWMutex
	increate_index bool   // 是否使用index自增
	flagID         uint16 // dnsid 前3位
	flagID2        uint16 // dnsid 后2位
	printStatus    bool
}

func (d *SendDog) Init(ether EthTable, dns []string, flagID uint16, printStatus bool) {
	d.ether = ether
	d.dns = dns
	d.flagID = flagID
	d.flagID2 = 0
	var (
		snapshot_len int32 = 1024
		promiscuous  bool  = false
		err          error
		timeout      time.Duration = -1 * time.Second
	)
	d.handle, err = pcap.OpenLive(d.ether.Device, snapshot_len, promiscuous, timeout)
	if err != nil {
		gologger.Fatalf("pcap初始化失败:%s\n", err.Error())
	}
	d.index = 10000
	d.increate_index = true
	d.lock = &sync.RWMutex{}
	d.printStatus = printStatus
	//defer d.handle.Close()
}
func (d *SendDog) Lock() {
	d.lock.Lock()
}
func (d *SendDog) UnLock() {
	d.lock.Unlock()
}
func (d *SendDog) ChoseDns() string {
	length := len(d.dns)
	if length > 0 && length <= 1 {
		return d.dns[0]
	} else {
		return d.dns[rand.Intn(len(d.dns)-1)]
	}
}
func (d *SendDog) BuildStatusTable(domain string, dns string, domainlevel int) (uint16, uint16) {
	// 生成本地状态表，返回需要的flagID和SrcPort参数
	d.lock.Lock()
	defer d.lock.Unlock()
	if d.index >= 60000 {
		d.flagID2++
		d.index = 10000
	}
	if d.flagID2 > 99 {
		d.increate_index = false
	}
	if d.increate_index {
		d.index++
	} else {
		for {
			v, error2 := LocalStack.Pop()
			if error2 == nil {
				d.flagID2, d.index = GenerateFlagIndexFromMap(v)
				break
			} else {
				time.Sleep(520 * time.Millisecond)
			}
		}
	}
	index := GenerateMapIndex(d.flagID2, d.index)
	if _, ok := LocalStauts.Load(index); !ok {
		LocalStauts.Store(uint32(index), StatusTable{Domain: domain, Dns: dns, Time: time.Now().Unix(), Retry: 0, DomainLevel: domainlevel})
	} else {
		gologger.Warningf("LocalStatus 状态重复")
	}
	return d.flagID2, d.index
}

func (d *SendDog) Send(domain string, dnsname string, srcport uint16, flagid uint16) {
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
		SrcPort: layers.UDPPort(srcport),
		DstPort: layers.UDPPort(53),
	}
	// Our DNS header
	dns := &layers.DNS{
		ID:      d.flagID*100 + flagid,
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
		gologger.Warningf("SerializeLayers faild:%s\n", err.Error())
	}
	err = d.handle.WritePacketData(buf.Bytes())
	if err != nil {
		gologger.Warningf("WritePacketDate error:%s\n", err.Error())
	}
	atomic.AddUint64(&SentIndex, 1)
	if d.printStatus {
		PrintStatus()
	}
}
func (d *SendDog) Close() {
	d.handle.Close()
}

func GenerateMapIndex(flagid2 uint16, index uint16) int {
	// 由flagid和index生成map中的唯一id
	return int(flagid2*60000) + int(index)
}
func GenerateFlagIndexFromMap(index uint32) (uint16, uint16) {
	// 从已经生成好的map index中返回flagid和index
	yuzhi := uint32(60000)
	flag2 := index / yuzhi
	index2 := index % yuzhi
	return uint16(flag2), uint16(index2)
}
