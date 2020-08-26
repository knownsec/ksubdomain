package main

import (
	"ksubdomain/core"
)

func main() {
	core.ShowBanner()
	defaultDns := []string{"223.5.5.5", "223.6.6.6", "180.76.76.76", "119.29.29.29", "182.254.116.116", "114.114.114.115"}

	filename := "/Users/boyhack/Downloads/Amass-master 2/examples/wordlists/all.txt"

	core.Start(&core.Options{Domain: "baidu.com", Rate: 30000, FileName: filename, Resolvers: defaultDns, Output: "", Test: false, NetworkId: 0, Silent: false, TTL: false, Verify: false, Stdin: false, Debug: true})
}
