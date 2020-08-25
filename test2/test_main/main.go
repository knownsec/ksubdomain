package main

import (
	"ksubdomain/core"
)

func main() {
	core.ShowBanner()
	defaultDns := []string{"223.5.5.5", "223.6.6.6", "180.76.76.76", "119.29.29.29", "182.254.116.116", "114.114.114.115"}

	core.Start(&core.Options{Domain: "qq.com", Rate: 30000, FileName: "", Resolvers: defaultDns, Output: "", Test: false, NetworkId: 0, Silent: false, TTL: false, Verify: false, Stdin: false})
}
