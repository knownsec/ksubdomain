package main

import (
	"ksubdomain/core"
)

func main() {
	bandwith := "2M" // K M G
	domain := ".qq.com"
	filename := "/Users/boyhack/study/子域名收集/源码资料/ESD-master/ESD/subs.esd"
	core.Start(domain, filename, bandwith)
}
