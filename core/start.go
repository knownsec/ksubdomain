package core

import (
	"bufio"
	"context"
	"fmt"
	"github.com/google/gopacket/pcap"
	ratelimit "golang.org/x/time/rate"
	"os"
	"strconv"
	"time"
)

func Start(domain string, filename string, bandwith string) {
	ShowBanner()
	if string(domain[0]) != "." {
		domain = "." + domain
	}
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
		fmt.Printf("unknown bandwith suffix '%s' (supported suffixes are G,M and K)\n", suffix)
	}
	packSize := int64(100) // 一个DNS包大概有74byte
	rate = rate / packSize

	version := pcap.Version()
	fmt.Println(version)
	ether := GetDevices()
	LocalStack = NewStack()
	go Recv(ether.Device)
	fmt.Println("启动接收模块,设置rate:", rate, "pps")
	dns := []string{"223.5.5.5", "223.6.6.6", "180.76.76.76", "119.29.29.29", "182.254.116.116", "114.114.114.114"}
	fmt.Println("Default DNS", dns)
	sendog := SendDog{}
	sendog.Init(ether, dns)
	defer sendog.Close()
	f, _ := os.Open(filename)
	defer f.Close()
	r := bufio.NewReader(f)

	limiter := ratelimit.NewLimiter(ratelimit.Every(time.Duration(time.Second.Nanoseconds()/rate)), 1000000)
	ctx := context.Background()
	// 协程重发线程
	go func() {
		for {
			// 循环检测超时的队列
			//遍历该map，参数是个函数，该函数参的两个参数是遍历获得的key和value，返回一个bool值，当返回false时，遍历立刻结束。
			LocalStauts.Range(func(k, v interface{}) bool {
				index := k.(uint32)
				value := v.(StatusTable)
				if value.Retry >= 10 {
					//fmt.Println("失败", value)
					LocalStauts.Delete(index)
					return true
				}
				if time.Now().Unix()-value.Time >= 5 {
					_ = limiter.Wait(ctx)
					value.Retry++
					value.Time = time.Now().Unix()
					value.Dns = sendog.ChoseDns()
					LocalStauts.Store(index, value)
					srcport := uint16(index)
					sendog.Send(value.Domain, value.Dns, srcport)
				}
				return true
			})
			time.Sleep(time.Second * 1)

		}
	}()
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
		_domain := msg + domain
		dnsname := sendog.ChoseDns()
		scrport := sendog.BuildStatusTable(_domain, dnsname)
		sendog.Send(_domain, dnsname, scrport)
	}

	for {
		var isbreak bool = true
		LocalStauts.Range(func(k, v interface{}) bool {
			isbreak = false
			return false
		})
		if isbreak {
			break
		}
		time.Sleep(700 * time.Millisecond)
	}
	fmt.Println("检测完毕,等待最后5s")
	time.Sleep(time.Second * 5)
}
