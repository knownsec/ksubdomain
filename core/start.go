package core

import (
	"bufio"
	"context"
	"github.com/google/gopacket/pcap"
	ratelimit "golang.org/x/time/rate"
	"io"
	"ksubdomain/gologger"
	"math/rand"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

func PrintStatus() {
	gologger.Printf("\rSuccess:%d Sent:%d Recved:%d Faild:%d", SuccessIndex, SentIndex, RecvIndex, FaildIndex)
}
func Start(options *Options) {
	version := pcap.Version()
	gologger.Infof(version + "\n")
	var ether EthTable
	if options.ListNetwork {
		GetIpv4Devices()
		os.Exit(0)
	}
	if options.NetworkId == -1 {
		ether = AutoGetDevices()
	} else {
		ether = GetDevices(options)
	}
	LocalStack = NewStack()
	// 设定接收的ID
	flagID := uint16(RandInt64(400, 654))
	retryChan := make(chan RetryStruct, options.Rate)
	go Recv(ether.Device, options, flagID, retryChan)
	sendog := SendDog{}
	sendog.Init(ether, options.Resolvers, flagID, true)

	var f io.Reader
	// handle Stdin
	if options.Stdin {
		if options.Verify {
			f = os.Stdin
		} else {
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Split(bufio.ScanLines)
			for scanner.Scan() {
				options.Domain = append(options.Domain, scanner.Text())
			}
		}
	}

	// handle dict
	if len(options.Domain) > 0 {
		if options.FileName == "" {
			gologger.Infof("加载内置字典\n")
			f = strings.NewReader(GetSubdomainData())
		} else {
			f2, err := os.Open(options.FileName)
			defer f2.Close()
			if err != nil {
				gologger.Fatalf("打开文件:%s 出现错误:%s\n", options.FileName, err.Error())
			}
			f = f2
		}
	}

	if options.Verify && options.FileName != "" {
		f2, err := os.Open(options.FileName)
		defer f2.Close()
		if err != nil {
			gologger.Fatalf("打开文件:%s 出现错误:%s\n", options.FileName, err.Error())
		}
		f = f2
	}

	if options.SkipWildCard {
		tmp_domains := []string{}
		gologger.Infof("检测泛解析\n")
		for _, domain := range options.Domain {
			if !IsWildCard(domain) {
				tmp_domains = append(tmp_domains, domain)
			} else {
				gologger.Warningf("域名:%s 存在泛解析记录,已跳过\n", domain)
			}
		}
		options.Domain = tmp_domains
	}
	// 仅使用api
	if options.API {
		s := &Source{}
		s.Init()
		gologger.Infof("API模块:%s\n", s.Names)
		for _, domain := range options.Domain {
			s.Feed(domain)
		}
		s.Wait()
		// 修改扫描模式为Verify
		options.Verify = true
		domains := make([]string, len(s.Domains))
		i := 0
		for k := range s.Domains {
			domains[i] = k
			i++
		}
		if options.FULL {
			r := bufio.NewReader(f)
			for {
				line, _, err := r.ReadLine()
				if err != nil {
					break
				}
				msg := string(line)
				for _, _domain := range options.Domain {
					_domain = msg + "." + _domain
					_, ok := s.Domains[_domain]
					if !ok {
						domains = append(domains, _domain)
					}
				}
			}
		}
		f = strings.NewReader(strings.Join(domains, "\n"))
		gologger.Infof("API模式获取完毕,验证中..\n")
	}

	if len(options.Domain) > 0 {
		gologger.Infof("检测域名:%s\n", options.Domain)
	}
	gologger.Infof("设置rate:%dpps\n", options.Rate)
	gologger.Infof("DNS:%s\n", options.Resolvers)

	r := bufio.NewReader(f)

	limiter := ratelimit.NewLimiter(ratelimit.Every(time.Duration(time.Second.Nanoseconds()/options.Rate)), int(options.Rate))
	ctx := context.Background()
	// 协程重发检测
	go func() {
		for {
			// 循环检测超时的队列
			maxLength := int(options.Rate / 10)
			datas := LocalStauts.GetTimeoutData(maxLength)
			isdelay := true
			if len(datas) <= 100 {
				isdelay = false
			}
			for _, localdata := range datas {
				index := localdata.index
				value := localdata.v
				if value.Retry >= 15 {
					atomic.AddUint64(&FaildIndex, 1)
					LocalStauts.SearchFromIndexAndDelete(index)
					continue
				}
				_ = limiter.Wait(ctx)
				value.Retry++
				value.Time = time.Now().Unix()
				value.Dns = sendog.ChoseDns()
				// 先删除，再重新创建
				LocalStauts.SearchFromIndexAndDelete(index)
				LocalStauts.Append(&value, index)
				flag2, srcport := GenerateFlagIndexFromMap(index)
				retryChan <- RetryStruct{Domain: value.Domain, Dns: value.Dns, SrcPort: srcport, FlagId: flag2, DomainLevel: value.DomainLevel}
				if isdelay {
					time.Sleep(time.Microsecond * time.Duration(rand.Intn(300)+100))
				}
			}
		}
	}()
	// 多级域名检测
	go func() {
		for {
			rstruct := <-retryChan
			if rstruct.SrcPort == 0 && rstruct.FlagId == 0 {
				flagid2, scrport := sendog.BuildStatusTable(rstruct.Domain, rstruct.Dns, rstruct.DomainLevel)
				rstruct.FlagId = flagid2
				rstruct.SrcPort = scrport
			}
			_ = limiter.Wait(ctx)
			sendog.Send(rstruct.Domain, rstruct.Dns, rstruct.SrcPort, rstruct.FlagId)
		}
	}()
	if f == nil {
		return
	}
	// 循环遍历发送
	for {
		line, _, err := r.ReadLine()
		if err != nil {
			break
		}
		msg := string(line)
		if options.Verify {
			dnsname := sendog.ChoseDns()
			flagid2, scrport := sendog.BuildStatusTable(msg, dnsname, 1)
			sendog.Send(msg, dnsname, scrport, flagid2)
		} else {
			for _, _domain := range options.Domain {
				_domain = msg + "." + _domain
				dnsname := sendog.ChoseDns()
				flagid2, scrport := sendog.BuildStatusTable(_domain, dnsname, 1)
				sendog.Send(_domain, dnsname, scrport, flagid2)
			}
		}
	}
	for {
		if LocalStauts.Empty() {
			break
		}
		time.Sleep(time.Millisecond * 723)
	}
	//gologger.Printf("\n")
	//for i := 5; i >= 0; i-- {
	//	gologger.Printf("检测完毕，等待%ds\n", i)
	//	time.Sleep(time.Second * 1)
	//}
	sendog.Close()
	if options.Summary {
		Summary()
	}
	if options.FilterWildCard {
		gologger.Printf("\n")
		data := FilterWildCard(options.Output)
		f, err1 := os.OpenFile(options.Output, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666) //打开文件
		if err1 != nil {
			gologger.Fatalf(err1.Error())
		}
		_, err2 := io.WriteString(f, strings.Join(data, "\n"))
		if err2 != nil {
			gologger.Fatalf(err2.Error())
		}
		gologger.Infof("文件保存成功:%s\n", options.Output)
	}
	if options.OutputCSV {
		gologger.Printf("\n")
		OutputExcel(options.Output)
	}
}
