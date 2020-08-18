package main

import (
	"fmt"
	"ksubdomain/core"
)

func main() {
	stack := core.NewStack()
	stack.Push(11)
	stack.Push(11)
	fmt.Println(stack.Pop())
	fmt.Println(stack.Pop())
	fmt.Println(stack.Pop())

}
