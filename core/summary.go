package core

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/logrusorgru/aurora"
	"ksubdomain/gologger"
	"strconv"
)

func Summary() {
	if len(AsnResults) == 0 {
		return
	}
	gologger.Infof("数据整理中...\n")
	asnData := GetAsnData()
	showData := make(map[AsnStruct][]string)
	// 整理
	for _, result := range AsnResults {
		subdomain := result.Subdomain
		for _, ips := range result.Answers {
			if ips.Type == layers.DNSTypeA {
				ip := ips.IP
				// 判断IP是否在ASN的范围中
				for _, asn := range asnData {
					if asn.Cidr.Contains(ip) {
						label := subdomain + "(" + ip.String() + ")"
						// www.baidu.com(14.215.177.39)
						showData[asn] = append(showData[asn], label)
						break
					}
				}
			}
		}
	}
	if len(showData) == 0 {
		gologger.Infof("未在ASN IP段上发现范围")
	}
	for asnKey, v := range showData {
		gologger.Printf(aurora.Blue("ASN:").String() + " " + aurora.Yellow(strconv.Itoa(asnKey.ASN)).String() + " - " + aurora.Green(asnKey.Registry).String() + "\n")
		countstr := fmt.Sprintf("\t%-4d", len(v))
		cidrstr := fmt.Sprintf("\t%-18s", asnKey.Cidr.String())
		gologger.Printf("%s%s\tSubdomain Name(s)\n", aurora.Yellow(cidrstr).String(), aurora.Yellow(countstr).String())
		subdomains := fmt.Sprintf("%s", v)
		gologger.Printf("\t%-4s\n", subdomains)
	}
}
