package core

import (
	"net"
	"sync"
)

// 本地状态表
type StatusTable struct {
	Domain      string // 查询域名
	Dns         string // 查询dns
	Time        int64  // 发送时间
	Retry       int    // 重试次数
	DomainLevel int    // 域名层级
}

// 重发状态数据结构
type RetryStruct struct {
	Domain      string
	Dns         string
	SrcPort     uint16
	FlagId      uint16
	DomainLevel int
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
