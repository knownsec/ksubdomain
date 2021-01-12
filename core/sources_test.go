package core

import "testing"

func TestSource_Feed(t *testing.T) {
	s := Source{}
	s.Init()
	s.Feed("baidu.com")
	s.Wait()
}
