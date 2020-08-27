package core

import (
	"net"
	"sync"
)

type StatusTable struct {
	Domain string // 查询域名
	Dns    string // 查询dns
	Time   int64  // 发送时间
	Retry  int    // 重试次数
}
type EthTable struct {
	SrcIp  net.IP
	Device string
	SrcMac net.HardwareAddr
	DstMac net.HardwareAddr
}

var wait_chain *Stack
var LocalStauts sync.Map
var DnsChoice sync.Map
var RecvIndex uint64 = 0
var FaildIndex uint64 = 0
var SentIndex uint64 = 0
var SuccessIndex uint64 = 0

func GetWaitChain() *Stack {
	if wait_chain == nil {
		return NewStack()
	} else {
		return wait_chain
	}
}
