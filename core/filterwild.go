package core

import (
	"fmt"
	"ksubdomain/gologger"
	"math"
	"sort"
	"strconv"
	"strings"
)

type Pair struct {
	Key   string
	Value int
}
type PairList []Pair

func (p PairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p PairList) Len() int           { return len(p) }
func (p PairList) Less(i, j int) bool { return p[i].Value > p[j].Value }

// A function to turn a map into a PairList, then sort and return it.
func sortMapByValue(m map[string]int) PairList {
	p := make(PairList, len(m))
	i := 0
	for k, v := range m {
		p[i] = Pair{k, v}
		i++
	}
	sort.Sort(p)
	return p
}

func FilterWildCard(filename string) []string {
	gologger.Infof("泛解析处理中...\n")
	result, err := LinesInFile(filename)
	if err != nil {
		gologger.Fatalf(err.Error())
	}
	record_sum := 0
	dd := make(map[string]int) // 统计每个记录的个数
	for _, line := range result {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		splits := strings.SplitN(line, " => ", 2)
		if len(splits) != 2 {
			continue
		}
		ips := splits[1]
		record_sum += 1
		for _, ip := range strings.Split(ips, " => ") {
			_, ok := dd[ip]
			if !ok {
				dd[ip] = 0
			}
			dd[ip] += 1
		}
	}
	pairlist := sortMapByValue(dd)
	dd3 := make(map[string]int) // 记录每个解析记录的权重值
	index := 0
	for _, v := range pairlist {
		index += 1
		quan := 0.0
		if index <= 15 && v.Value > 1000 {
			quan, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", 15-float64(index)/15*80), 64)
		}
		_quan, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", float64(v.Value)/float64(record_sum)*100), 64)
		quan += _quan
		if v.Value > 100 && quan < 10 {
			quan += 10
		}
		if quan > 100 {
			quan = 100
		}
		dd3[v.Key] = int(math.Ceil(quan))
	}
	// 根据权值过滤域名
	var result2 []string
	set := make(map[int]int)
	for _, line := range result {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		splits := strings.SplitN(line, " => ", 2)
		//domain := splits[0]
		ips := splits[1]
		ips_split := strings.Split(ips, " => ")
		quan := 0
		for _, ip := range ips_split {
			_quan, _ := dd3[ip]
			quan += _quan
		}
		avg := quan / len(ips_split)
		if avg > 60 {
			_, ok := set[avg]
			if !ok {
				set[avg] = 0
			} else {
				continue
			}
		}
		result2 = append(result2, line)
	}
	gologger.Infof("泛解析过滤完成，过滤前数据量:%d 过滤后数据量:%d\n", record_sum, len(result2))
	return result2
}
