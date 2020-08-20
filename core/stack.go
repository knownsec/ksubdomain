package core

import (
	"errors"
	"sync"
)

type (
	Stack struct {
		top    *node
		length int
		lock   *sync.RWMutex
	}
	node struct {
		value uint32
		prev  *node
	}
)

var LocalStack *Stack

// Create a new stack
func NewStack() *Stack {
	return &Stack{nil, 0, &sync.RWMutex{}}
}

// Return the number of items in the stack
func (this *Stack) Len() int {
	return this.length
}

func (this *Stack) Empty() bool {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.length > 0
}

// Pop the top item of the stack and return it
func (this *Stack) Pop() (uint32, error) {
	this.lock.Lock()
	defer this.lock.Unlock()
	if this.length == 0 {
		return 0, errors.New("Stack length is empty")
	}
	n := this.top
	this.top = n.prev
	this.length--
	return n.value, nil
}

// Push a value onto the top of the stack
func (this *Stack) Push(value uint32) {
	this.lock.Lock()
	defer this.lock.Unlock()
	n := &node{value, this.top}
	this.top = n
	this.length++
}
