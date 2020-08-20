package main

import (
	"flag"
	"ksubdomain/core"
	"os"
)

var flag_bandwith = flag.String("b", "1M", "宽带的下行速度，可以5M,5K,5G")
var flag_domain = flag.String("d", "", "爆破域名")
var flag_filename = flag.String("f", "", "爆破字典路径")

func main() {
	flag.Parse()
	bandwith := *flag_bandwith // K M G
	domain := *flag_domain
	filename := *flag_filename
	if domain == "" || filename == "" {
		flag.Usage()
		os.Exit(0)
	}
	core.Start(domain, filename, bandwith)
}
