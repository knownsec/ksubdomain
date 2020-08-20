package main

import (
	"fmt"
	"time"
)

func main() {
	now := time.Now().Unix()
	fmt.Println(now)
	time.Sleep(5 * time.Second)
	fmt.Println(time.Now().Unix() - now)
	//fmt.Println(string("aaaa"[1]))
}
