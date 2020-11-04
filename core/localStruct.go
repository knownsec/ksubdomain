package core

import (
	"errors"
	"sync"
	"time"
)

type (
	LocalStruct struct {
		items []localNode
		lock  sync.RWMutex
	}
	localNode struct {
		v     StatusTable
		index uint32
	}
	LocalRetryStruct struct {
		v     StatusTable
		index uint32
	}
)

// Create a new stack
func NewLocalStruct() *LocalStruct {
	return &LocalStruct{[]localNode{}, sync.RWMutex{}}
}

// Return the number of items in the stack
func (this *LocalStruct) Len() int {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return len(this.items)
}

func (this *LocalStruct) Empty() bool {
	return this.Len() == 0
}

func (this *LocalStruct) Append(node *StatusTable, index uint32) {
	this.lock.Lock()
	defer this.lock.Unlock()
	newNode := localNode{*node, index}
	this.items = append(this.items, newNode)
}

// 搜索并删除节点
func (this *LocalStruct) SearchFromIndexAndDelete(index uint32) (LocalRetryStruct, error) {
	this.lock.Lock()
	defer this.lock.Unlock()

	for i := 0; i < len(this.items); i++ {
		if this.items[i].index == index {
			ret := LocalRetryStruct{this.items[i].v, index}
			this.items = append(this.items[:i], this.items[i+1:]...)
			return ret, nil
		}
	}
	return LocalRetryStruct{}, errors.New("data not found")
}

// 从链表中取出超时的数据，可选每次取出最多多少数据
func (this *LocalStruct) GetTimeoutData(max int) []LocalRetryStruct {
	this.lock.Lock()
	defer this.lock.Unlock()
	currentTime := time.Now().Unix()
	index := 0
	var tables []LocalRetryStruct
	j := 0
	for i := 0; i < len(this.items); i++ {
		if currentTime-this.items[i].v.Time < 5 {
			break
		}
		if index > max {
			break
		}
		index++
		j = i
		tables = append(tables, LocalRetryStruct{this.items[i].v, this.items[i].index})
	}
	if len(tables) > 0 {
		this.items = append(this.items[j+1:])
	}
	return tables
}
