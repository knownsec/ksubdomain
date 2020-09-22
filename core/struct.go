package core

import (
	"github.com/google/gopacket/layers"
	"net"
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

// 接收结果数据结构
type RecvResult struct {
	Subdomain string
	Answers   []layers.DNSResourceRecord
}

// ASN数据结构
type AsnStruct struct {
	ASN      int
	Registry string
	Cidr     *net.IPNet
}

type EthTable struct {
	SrcIp  net.IP
	Device string
	SrcMac net.HardwareAddr
	DstMac net.HardwareAddr
}

var wait_chain *Stack
var LocalStauts LocalStruct
var RecvIndex uint64 = 0
var FaildIndex uint64 = 0
var SentIndex uint64 = 0
var SuccessIndex uint64 = 0
var AsnResults []RecvResult

func GetWaitChain() *Stack {
	if wait_chain == nil {
		return NewStack()
	} else {
		return wait_chain
	}
}
