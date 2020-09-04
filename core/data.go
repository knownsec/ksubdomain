package core

import (
	"bufio"
	"github.com/rakyll/statik/fs"
	_ "ksubdomain/core/statik"
	"ksubdomain/gologger"
	"net"
	"strconv"
	"strings"
)

func GetAsnData() []AsnStruct { //[]AsnStruct
	var asnData []AsnStruct = []AsnStruct{}
	statikFS, err := fs.New()
	if err != nil {
		gologger.Fatalf(err.Error())
	}
	r, err := statikFS.Open("/asn.txt")
	if err != nil {
		gologger.Fatalf("打开资源文件失败:%s", err.Error())
	}
	defer r.Close()
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		err := scanner.Err()
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 4 {
			gologger.Fatalf("错误:%s", line)
		}
		asnid, _ := strconv.Atoi(parts[2])
		startIP := net.ParseIP(parts[0]).To4()
		endIP := net.ParseIP(parts[1]).To4()
		asnData = append(asnData, AsnStruct{
			ASN: asnid, Registry: parts[3], Cidr: Range2CIDR(startIP, endIP)})
	}
	return asnData
}
