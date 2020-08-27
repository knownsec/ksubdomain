package main

import (
	"fmt"
	"ksubdomain/core"
	"net"
	"os"
	"time"
)

func test(options *core.Options) {
	sendog := core.SendDog{}
	ether := core.GetDevices(options.NetworkId)
	ether.DstMac = net.HardwareAddr{0x5c, 0xc9, 0x09, 0x33, 0x34, 0x80}
	sendog.Init(ether, []string{"8.8.8.8"}, 404)
	defer sendog.Close()
	var index int64 = 0
	start := time.Now().UnixNano() / 1e6
	flag := int64(15) // 15s
	var now int64
	for {
		sendog.Send("seebug.org", "8.8.8.8", 1234, 1)
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
}
func main() {
	options := core.ParseOptions()
	if options.Test {
		test(options)
		os.Exit(0)
	}
	core.Start(options)
}
