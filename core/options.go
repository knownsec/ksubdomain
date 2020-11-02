package core

import (
	"flag"
	"ksubdomain/gologger"
	"os"
	"strconv"
)

type Options struct {
	Rate            int64
	Domain          []string
	FileName        string
	Resolvers       []string
	Output          string
	Test            bool
	NetworkId       int
	Silent          bool
	TTL             bool
	Verify          bool
	Stdin           bool
	Debug           bool
	DomainLevel     int
	SkipWildCard    bool
	Summary         bool
	SubNameFileName string // 三级域名字典文件
	FilterWildCard  bool   // 过滤泛解析结果
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}

	bandwith := flag.String("b", "1M", "宽带的下行速度，可以5M,5K,5G")
	domain := flag.String("d", "", "爆破域名")
	domain_list := flag.String("dl", "", "从文件中读取爆破域名")
	flag.StringVar(&options.FileName, "f", "", "字典路径,-d下文件为子域名字典，-verify下文件为需要验证的域名")
	flag.StringVar(&options.SubNameFileName, "sf", "", "三级域名爆破字典文件(默认内置)")
	resolvers := flag.String("s", "", "resolvers文件路径,默认使用内置DNS")
	flag.StringVar(&options.Output, "o", "", "输出文件路径")
	flag.BoolVar(&options.Test, "test", false, "测试本地最大发包数")
	flag.IntVar(&options.NetworkId, "e", -1, "默认网络设备ID,默认-1，如果有多个网络设备会在命令行中选择")
	flag.BoolVar(&options.Silent, "silent", false, "使用后屏幕将仅输出域名")
	flag.BoolVar(&options.TTL, "ttl", false, "导出格式中包含TTL选项")
	flag.BoolVar(&options.Verify, "verify", false, "验证模式")
	flag.IntVar(&options.DomainLevel, "l", 1, "爆破域名层级,默认爆破一级域名")
	flag.BoolVar(&options.SkipWildCard, "skip-wild", false, "跳过泛解析的域名")
	flag.BoolVar(&options.FilterWildCard, "filter-wild", false, "自动分析并过滤泛解析，最终输出文件，需要与'-o'搭配")
	flag.BoolVar(&options.Summary, "summary", false, "在扫描完毕后整理域名归属asn以及IP段")
	flag.Parse()
	options.Stdin = hasStdin()
	if options.Silent {
		gologger.MaxLevel = gologger.Silent
	}
	ShowBanner()
	// handle resolver
	if *resolvers != "" {
		rs, err := LinesInFile(*resolvers)
		if err != nil {
			gologger.Fatalf("读取resolvers文件失败:%s\n", err.Error())
		}
		if len(rs) == 0 {
			gologger.Fatalf("resolvers文件内容为空\n")
		}
		options.Resolvers = rs
	} else {
		defaultDns := []string{"223.5.5.5", "223.6.6.6", "180.76.76.76", "119.29.29.29", "182.254.116.116", "114.114.114.115"}
		options.Resolvers = defaultDns
	}
	// handle domain
	if *domain != "" {
		options.Domain = append(options.Domain, *domain)
	}
	if *domain_list != "" {
		dl, err := LinesInFile(*domain_list)
		if err != nil {
			gologger.Fatalf("读取domain文件失败:%s\n", err.Error())
		}
		options.Domain = append(dl, options.Domain...)
	}
	var rate int64
	suffix := string([]rune(*bandwith)[len(*bandwith)-1])
	rate, _ = strconv.ParseInt(string([]rune(*bandwith)[0:len(*bandwith)-1]), 10, 64)
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
		gologger.Fatalf("unknown bandwith suffix '%s' (supported suffixes are G,M and K)\n", suffix)
	}
	packSize := int64(100) // 一个DNS包大概有74byte
	rate = rate / packSize
	options.Rate = rate
	if len(options.Domain) == 0 && !hasStdin() && (!options.Verify && options.FileName == "") && !options.Test {
		flag.Usage()
		os.Exit(0)
	}
	if len(options.Domain) > 0 && options.Verify {
		gologger.Fatalf("-d 与 -verify参数不可以同时出现!")
	}
	if options.FileName != "" && !FileExists(options.FileName) {
		gologger.Fatalf("文件:%s 不存在!\n", options.FileName)
	}
	if !options.Stdin && options.Verify && options.FileName == "" {
		gologger.Fatalf("启用了 -verify 参数但传入域名为空!")
	}
	if options.FilterWildCard && options.Output == "" {
		gologger.Fatalf("启用了 -filter-wild后，需要搭配一个输出文件 '-o'")
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
