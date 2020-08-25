package core

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
)

type Options struct {
	Rate      int64
	Domain    string
	FileName  string
	Resolvers []string
	Output    string
	Test      bool
	NetworkId int
	Silent    bool
	TTL       bool
	Verify    bool
	Stdin     bool
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}
	bandwith := *flag.String("b", "1M", "宽带的下行速度，可以5M,5K,5G")
	flag.StringVar(&options.Domain, "d", "", "爆破域名")
	flag.StringVar(&options.FileName, "f", "", "字典路径,-d下文件为子域名字典，-verify下文件为需要验证的域名")
	resolvers := *flag.String("s", "", "resolvers文件路径,默认使用内置DNS")
	flag.StringVar(&options.Output, "o", "", "输出文件路径")
	flag.BoolVar(&options.Test, "test", false, "测试本地最大发包数")
	flag.IntVar(&options.NetworkId, "e", -1, "默认网络设备ID,默认-1，如果有多个网络设备会在命令行中选择")
	flag.BoolVar(&options.Silent, "silent", false, "使用后屏幕将不会输出结果")
	flag.BoolVar(&options.TTL, "ttl", false, "导出格式中包含TTL选项")
	flag.BoolVar(&options.Verify, "verify", false, "验证模式")
	flag.Parse()
	options.Stdin = hasStdin()
	ShowBanner()
	// handle resolver
	if resolvers != "" {
		rs, err := LinesInFile(resolvers)
		if err != nil {
			log.Panic(err)
		}
		options.Resolvers = rs
	} else {
		defaultDns := []string{"223.5.5.5", "223.6.6.6", "180.76.76.76", "119.29.29.29", "182.254.116.116", "114.114.114.115"}
		options.Resolvers = defaultDns
	}
	var rate int64
	suffix := string([]rune(bandwith)[len(bandwith)-1])
	rate, _ = strconv.ParseInt(string([]rune(bandwith)[0:len(bandwith)-1]), 10, 64)
	switch suffix {
	case "G":
		fallthrough
	case "g":
		rate *= 1000000000
	case "M":
		fallthrough
	case "m":
		rate *= 1000000
	case "K":
		fallthrough
	case "k":
		rate *= 1000
	default:
		fmt.Printf("unknown bandwith suffix '%s' (supported suffixes are G,M and K)\n", suffix)
	}
	packSize := int64(100) // 一个DNS包大概有74byte
	rate = rate / packSize
	options.Rate = rate
	if options.Domain == "" && !hasStdin() && (!options.Verify && options.FileName == "") {
		flag.Usage()
		os.Exit(0)
	}
	return options
}
func hasStdin() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	if fi.Mode()&os.ModeNamedPipe == 0 {
		return false
	}
	return true
}
