package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"log"
)

func main() {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print device information
	fmt.Println("Devices found:")
	for _, d := range devices {
		for _, address := range d.Addresses {
			ip := address.IP
			if ip.To4() != nil && !ip.IsLoopback() {
				fmt.Println("Name: ", d.Name)
				fmt.Println("Description: ", d.Description)
				fmt.Println("Devices addresses: ", d.Description)
				fmt.Println("- IP address: ", address.IP)
				fmt.Println("- Subnet mask: ", address.Netmask)
			}
		}
	}
}
