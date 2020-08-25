package core

import (
	"bufio"
	"context"
	"fmt"
	"github.com/google/gopacket/pcap"
	ratelimit "golang.org/x/time/rate"
	"io"
	"math/rand"
	"os"
	"strings"
	"time"
)

func Start(options *Options) {
	version := pcap.Version()
	fmt.Println(version)
	ether := GetDevices(options.NetworkId)
	LocalStack = NewStack()
	go Recv(ether.Device, options)
	fmt.Println("启动接收模块,设置rate:", options.Rate, "pps")
	fmt.Println("DNS:", options.Resolvers)
	sendog := SendDog{}
	sendog.Init(ether, options.Resolvers)
	defer sendog.Close()
	var f io.Reader
	if options.Stdin {
		f = os.Stdin
	} else if options.Domain != "" {
		if options.FileName == "" {
			fmt.Println("加载内置字典")
			f = strings.NewReader(DefaultSubdomain)
		} else {
			f2, err := os.Open(options.FileName)
			defer f2.Close()
			if err != nil {
				panic(err)
			}
			f = f2
		}
	} else if options.Verify {
		f2, err := os.Open(options.FileName)
		defer f2.Close()
		if err != nil {
			panic(err)
		}
		f = f2
	}
	r := bufio.NewReader(f)

	limiter := ratelimit.NewLimiter(ratelimit.Every(time.Duration(time.Second.Nanoseconds()/options.Rate)), 1000000)
	ctx := context.Background()
	// 协程重发线程
	go func() {
		for {
			// 循环检测超时的队列
			//遍历该map，参数是个函数，该函数参的两个参数是遍历获得的key和value，返回一个bool值，当返回false时，遍历立刻结束。
			LocalStauts.Range(func(k, v interface{}) bool {
				index := k.(uint32)
				value := v.(StatusTable)
				if value.Retry >= 30 {
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
				time.Sleep(time.Millisecond * time.Duration(rand.Intn(300)+100))
				return true
			})
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
		var _domain string
		if options.Verify || options.Stdin {
			_domain = msg
		} else {
			_domain = msg + "." + options.Domain
		}
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
