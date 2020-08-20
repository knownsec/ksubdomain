package main

import (
	"flag"
	"fmt"
	"ksubdomain/core"
	"log"
	"net"
	"os"
	"time"
)

var flag_bandwith = flag.String("b", "1M", "宽带的下行速度，可以5M,5K,5G")
var flag_domain = flag.String("d", "", "爆破域名")
var flag_filename = flag.String("f", "", "爆破字典路径")
var flag_resolvers = flag.String("s", "", "resolvers文件路径")
var flag_output = flag.String("o", "", "输出文件路径")
var flag_test = flag.Bool("test", false, "测试本地最大发包数")

func main() {
	flag.Parse()
	bandwith := *flag_bandwith // K M G
	domain := *flag_domain
	filename := *flag_filename
	if *flag_test {
		sendog := core.SendDog{}
		ether := core.GetDevices()
		ether.DstMac = net.HardwareAddr{0x5c, 0xc9, 0x09, 0x33, 0x34, 0x80}
		sendog.Init(ether, []string{"8.8.8.8"})
		defer sendog.Close()
		var index int64 = 0
		start := time.Now().UnixNano() / 1e6
		flag := int64(15) // 15s
		var now int64
		for {
			sendog.Send("seebug.org", "8.8.8.8", 1234)
			index++
			now = time.Now().UnixNano() / 1e6
			tickTime := (now - start) / 1000
			if tickTime >= flag {
				break
			}
			if (now-start)%1000 == 0 && now-start >= 900 {
				tickIndex := index / tickTime
				fmt.Printf("\r %ds 总发送:%d Packet 平均每秒速度:%dpps", tickTime, index, tickIndex)
			}
		}
		now = time.Now().UnixNano() / 1e6
		tickTime := (now - start) / 1000
		tickIndex := index / tickTime
		fmt.Printf("\r %ds 总发送:%d Packet 平均每秒速度:%dpps\n", tickTime, index, tickIndex)
		os.Exit(0)
	}
	stat, _ := os.Stdin.Stat()
	if (domain == "" || filename == "") && int(stat.Mode()&os.ModeNamedPipe) == 0 {
		flag.Usage()
		os.Exit(0)
	}
	resolvers := []string{}
	if *flag_resolvers != "" {
		rs, err := core.LinesInFile(*flag_resolvers)
		if err != nil {
			log.Panic(err)
		}
		resolvers = rs
	}
	core.Start(domain, filename, bandwith, resolvers, *flag_output)
}
