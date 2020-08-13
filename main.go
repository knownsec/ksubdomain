package main

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket/pcap"
	"ksubdomain/core"
	"os"
)

func main() {
	fmt.Println("ksubdomain v1.0")
	//  获取 libpcap 的版本
	version := pcap.Version()
	fmt.Println("pcap version:" + version)
	ether := core.GetDevices()
	go core.Recv(ether.Device)
	fmt.Println("启动接收模块")
	dns := []string{"1.1.1.1"}
	sendog := core.SendDog{}
	sendog.Init(ether, dns)
	defer sendog.Close()
	filename := "/Users/boyhack/goprograms/src/pcap-subdom/subdomain.txt"
	f, _ := os.Open(filename)
	defer f.Close()
	r := bufio.NewReader(f)

	for {
		line, _, err := r.ReadLine()
		if err != nil {
			break
		}
		msg := string(line)
		if msg == "" {
			break
		}
		sendog.Send(msg + ".baidu.com")
		//time.Sleep(time.Microsecond * 10)
	}
	fmt.Println("发完，等待中")
	for {
	}
}
