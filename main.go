package main

import (
	"bufio"
	"context"
	"fmt"
	"github.com/google/gopacket/pcap"
	ratelimit "golang.org/x/time/rate"
	"ksubdomain/core"
	"log"
	"os"
	"strconv"
	"time"
)

func main() {
	fmt.Println("ksubdomain v1.0")
	//  获取 libpcap 的版本
	bandwith := "10M" // K M G
	var rate int64
	suffix := string([]rune(bandwith)[len(bandwith)-1])
	rate, _ = strconv.ParseInt(string([]rune(bandwith)[0:len(bandwith)-1]), 10, 64)
	switch suffix {
	case "G":
		fallthrough
	case "g":
		rate *= 1000000000
	case "M":
		fallthrough
	case "m":
		rate *= 1000000
	case "K":
		fallthrough
	case "k":
		rate *= 1000
	default:
		log.Panicf("unknown bandwith suffix '%s' (supported suffixes are G,M and K)", suffix)
	}
	packSize := int64(100) // 一个DNS包大概有74byte
	rate = rate / packSize

	version := pcap.Version()
	fmt.Println(version)
	ether := core.GetDevices()
	go core.Recv(ether.Device)
	fmt.Println("启动接收模块")
	dns := []string{"223.5.5.5", "223.6.6.6", "180.76.76.76", "119.29.29.29", "182.254.116.116", "114.114.114.114"}
	sendog := core.SendDog{}
	sendog.Init(ether, dns)
	defer sendog.Close()
	filename := "/Users/boyhack/goproject/subdomain_brust/sub2.txt"
	f, _ := os.Open(filename)
	defer f.Close()
	r := bufio.NewReader(f)

	limiter := ratelimit.NewLimiter(ratelimit.Every(time.Duration(time.Second.Nanoseconds()/rate)), 1000000)
	ctx := context.Background()
	for {
		_ = limiter.Wait(ctx)
		line, _, err := r.ReadLine()
		if err != nil {
			break
		}
		msg := string(line)
		if msg == "" {
			break
		}
		domain := msg + ".baidu.com"
		dnsname := sendog.ChoseDns()
		dnsid, scrport := sendog.BuildStatusTable(domain, dnsname)
		sendog.Send(domain, dnsname, dnsid, scrport)
		//time.Sleep(time.Microsecond * 1000)
	}
	fmt.Println("发完，等待中")
	for {
		// 循环检测超时的队列
		//遍历该map，参数是个函数，该函数参的两个参数是遍历获得的key和value，返回一个bool值，当返回false时，遍历立刻结束。
		core.LocalStauts.Range(func(k, v interface{}) bool {
			index := k.(uint32)
			value := v.(core.StatusTable)
			if value.Retry >= 30 {
				fmt.Println("失败", value)
				return true
			}
			if time.Now().Unix()-value.Time >= 5 {
				value.Retry++
				value.Time = time.Now().Unix()
				core.LocalStauts.Store(index, value)
				var dnsid, srcport uint16
				if index <= 60000 {
					dnsid = 0 + 40400
					srcport = uint16(index)
				} else {
					dnsid = uint16(index/60000 + 40400)
					srcport = uint16(index % 10000)
				}
				sendog.Send(value.Domain, value.Dns, dnsid, srcport)
			}
			return true
		})
		time.Sleep(time.Second * 2)
	}
}
