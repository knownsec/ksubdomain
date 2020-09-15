package core

import (
	"bufio"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"ksubdomain/gologger"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func Recv(device string, options *Options, flagID uint16, retryChan chan RetryStruct) {
	var (
		snapshotLen int32         = 1024
		promiscuous bool          = false
		timeout     time.Duration = -1 * time.Second
	)
	windowWith := GetWindowWith()
	if options.Silent {
		windowWith = 0
	}
	handle, _ := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	err := handle.SetBPFFilter("udp and port 53")
	if err != nil {
		gologger.Fatalf("SetBPFFilter Faild:%s\n", err.Error())
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	defer handle.Close()

	var udp layers.UDP
	var dns layers.DNS
	var eth layers.Ethernet
	var ipv4 layers.IPv4

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet, &eth, &ipv4, &udp, &dns)
	var isWrite bool = false
	var isttl bool = options.TTL

	var scname string = options.Scname
	var isSummary bool = options.Summary
	if options.Output != "" {
		isWrite = true
	}
	var foutput *os.File
	if isWrite {
		foutput, err = os.OpenFile(options.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
		if err != nil {
			gologger.Errorf("写入结果文件失败：%s\n", err.Error())
		}
	}
	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			continue
		}
		var decoded []gopacket.LayerType
		err = parser.DecodeLayers(packet.Data(), &decoded)
		if err != nil {
			continue
		}
		if !dns.QR {
			continue
		}
		if dns.ID/100 == flagID {
			var drop bool = false
			atomic.AddUint64(&RecvIndex, 1)
			udp, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
			index := GenerateMapIndex(dns.ID%100, uint16(udp.DstPort))
			if dns.ANCount > 0 {
				atomic.AddUint64(&SuccessIndex, 1)
				if len(dns.Questions) == 0 {
					continue
				}
				data := RecvResult{Subdomain: string(dns.Questions[0].Name)}
				data.Answers = dns.Answers

				msg := data.Subdomain + " => "
				if !options.Silent {
					for _, v := range data.Answers {
						msg += v.String()
						if isttl {
							msg += " ttl:" + strconv.Itoa(int(v.TTL))
						}

						msg += " => "
					}
				}
				if strings.Contains(msg, "CNAME " + scname) && scname != ""{
					//  处理cname 黑名单
					drop = true
				}
				if !drop {
					msg = strings.Trim(msg, " => ")
					ff := windowWith - len(msg) - 1
					if windowWith > 0 && ff > 0 {
						gologger.Silentf("\r%s% *s\n", msg, ff, "")
					} else {
						gologger.Silentf("\r%s\n", msg)
					}
					if isSummary {
						AsnResults = append(AsnResults, data)
					}
					if isWrite {
						w := bufio.NewWriter(foutput)
						_, err = w.WriteString(msg + "\n")
						if err != nil {
							gologger.Errorf("写入结果文件失败.\n", err.Error())
						}
						_ = w.Flush()
					}
				}
			}
			if _data, ok := LocalStauts.Load(uint32(index)); ok {
				data := _data.(StatusTable)
				// 处理多级域名
				if dns.ANCount > 0 && data.DomainLevel < options.DomainLevel && !drop {
					running := true
					if options.SkipWildCard {
						if IsWildCard(data.Domain) {
							running = false
						}
					}
					if running {
						for _, sub := range GetSubNextData() {
							subdomain := sub + "." + data.Domain
							retryChan <- RetryStruct{Domain: subdomain, Dns: data.Dns, SrcPort: 0, FlagId: 0, DomainLevel: data.DomainLevel + 1}
						}
					}
				}
				if LocalStack.Len() <= 50000 {
					LocalStack.Push(uint32(index))
				}
				LocalStauts.Delete(uint32(index))
			}
			PrintStatus()
		}
	}
}
