package core

import "net"

type EthTable struct {
	SrcIp  net.IP
	Device string
	SrcMac net.HardwareAddr
	DstMac net.HardwareAddr
}

