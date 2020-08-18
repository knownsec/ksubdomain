package core

func Init() {
	wait_chain := GetWaitChain()
	// 填充10000~60000
	for i := 1; i < 60000; i++ {
		wait_chain.Push(uint32(i))
	}
}
