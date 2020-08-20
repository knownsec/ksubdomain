package main

import (
	"ksubdomain/core"
)

func main() {
	bandwith := "1M" // K M G
	domain := ".baidu.com"
	filename := "/Users/boyhack/goproject/subdomain_brust/sub2.txt"
	core.Start(domain, filename, bandwith)
}
