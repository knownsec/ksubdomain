package main

import (
	"ksubdomain/core"
)

func main() {
	core.ShowBanner()
	core.Start(&core.Options{Domain: "qq.com", Rate: 30000, FileName: "", Resolvers: []string{"8.8.8.8"}, Output: "", Test: false, NetworkId: 0, Silent: false, TTL: false, Verify: false, Stdin: false})
}
