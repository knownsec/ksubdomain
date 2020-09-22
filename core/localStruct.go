package core

import (
	"errors"
	"sync"
	"time"
)

type (
	LocalStruct struct {
		header *localNode
		length int
		lock   sync.RWMutex
	}
	localNode struct {
		v     *StatusTable
		index uint32
		next  *localNode
	}
	LocalRetryStruct struct {
		v     StatusTable
		index uint32
	}
)

// Create a new stack
func NewLocalStruct() *LocalStruct {
	return &LocalStruct{nil, 0, sync.RWMutex{}}
}

// Return the number of items in the stack
func (this *LocalStruct) Len() int {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.length
}

func (this *LocalStruct) Empty() bool {
	return this.Len() == 0
}

func (this *LocalStruct) Append(node *StatusTable, index uint32) {
	newNode := &localNode{node, index, nil}
	if this.Empty() {
		this.lock.Lock()
		this.header = newNode
		this.lock.Unlock()
	} else {
		this.lock.Lock()
		current := this.header
		for current.next != nil {
			current = current.next
		}
		current.next = newNode
		this.lock.Unlock()
	}
	this.lock.Lock()
	this.length++
	this.lock.Unlock()
}

// 搜索并删除节点
func (this *LocalStruct) SearchFromIndexAndDelete(index uint32) (LocalRetryStruct, error) {
	this.lock.Lock()
	defer this.lock.Unlock()
	prev := this.header
	if prev == nil {
		return LocalRetryStruct{}, errors.New("data length is null")
	}
	if prev.index == index {
		v := *prev.v
		this.header = prev.next
		this.length--
		return LocalRetryStruct{v, index}, nil
	}
	for prev.next != nil {
		if prev.next.index == index {
			v := *prev.next.v
			after := prev.next.next
			prev.next = after
			this.length--
			return LocalRetryStruct{v, index}, nil
		}
		prev = prev.next
	}
	return LocalRetryStruct{}, errors.New("data not found")
}

// 从链表中取出超时的数据，可选每次取出最多多少数据
func (this *LocalStruct) GetTimeoutData(max int) []LocalRetryStruct {
	this.lock.Lock()
	defer this.lock.Unlock()
	current := this.header
	currentTime := time.Now().Unix()
	index := 0
	var tables []LocalRetryStruct
	for current != nil {
		if currentTime-current.v.Time < 5 {
			break
		}
		if index > max {
			break
		}
		index++
		tables = append(tables, LocalRetryStruct{*current.v, current.index})
		current = current.next
	}
	// 删除掉这些选择的链表数据
	if index > 0 {
		this.header = current
		this.length -= index
	}
	return tables
}
