package main

import (
	"bufio"
	"fmt"
	"ksubdomain/core"
	"strings"
)

func main() {
	//output := "/Users/boyhack/GolandProjects/ksubdomain/test.txt"
	//foutput, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	//if err != nil {
	//	log.Panicln(err)
	//}
	//defer foutput.Close()
	//w := bufio.NewWriter(foutput)
	//defer w.Flush()
	//msg := "aaaaaaaaaa\n"
	//_, _ = w.WriteString(msg)
	//
	//_, _ = w.WriteString("bbbbbbbbbb\n")
	f := strings.NewReader(core.DefaultSubdomain)
	r := bufio.NewReader(f)
	for {
		line, _, err := r.ReadLine()
		if err != nil {
			break
		}
		fmt.Println(string(line))
	}

}
