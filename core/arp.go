package core

//func ArpScan(){
//	//Set up ARP client with socket
//	c, err := arp.Dial(inter)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer c.Close()
//
//	// Set request deadline from flag
//	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
//		log.Fatal(err)
//	}
//
//	// Request hardware address for IP address
//	ip := ip.IP
//	mac, err := c.Resolve(ip)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	fmt.Printf("%s -> %s", ip, mac)
//
//}
