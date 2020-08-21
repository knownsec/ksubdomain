package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("fail to get net interfaces: %v", err)
	}

	for _, netInterface := range netInterfaces {
		interfaceName := netInterface.Name
		inter, err := net.InterfaceByName(interfaceName)
		if err != nil {
			log.Fatalf("无法获取信息: %v", err)
		}

		addrs, err := inter.Addrs()

		if err != nil {
			log.Fatalln(err)
		}
		// 获取IP地址，子网掩码
		for _, addr := range addrs {
			if ip, ok := addr.(*net.IPNet); ok && !ip.IP.IsLoopback() {
				if ip.IP.To4() != nil {
					fmt.Println("Name:", interfaceName)
					fmt.Println("IP:", ip.IP)
					fmt.Println("Mask:", ip.Mask)
					fmt.Println("Mac:", inter.HardwareAddr.String())
				}
			}
		}
	}
}
