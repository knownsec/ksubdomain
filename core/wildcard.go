package core

import "net"

func IsWildCard(domain string) bool {
	ranges := [2]int{}
	for _, _ = range ranges {
		subdomain := RandomStr(6) + "." + domain
		_, err := net.LookupIP(subdomain)
		if err != nil {
			continue
		}
		return true
	}
	return false
}
