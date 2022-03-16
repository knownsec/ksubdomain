package core

import (
	"github.com/logrusorgru/aurora"
	"ksubdomain/gologger"
	"sync"
)

type void struct{}

type Source struct {
	script  []Script
	Names   []string
	Domains map[string]void
	wg      *sync.WaitGroup
	mu      *sync.Mutex
	limiter chan bool
}

func (s *Source) Init() {
	s.wg = &sync.WaitGroup{}
	s.mu = &sync.Mutex{}
	s.limiter = make(chan bool, 10)
	s.Domains = make(map[string]void)
	scripts := getDefaultScripts()
	for _, script := range scripts {
		tmp_script := Script{}
		tmp_script.newLuaState(script)
		scName, err := tmp_script.ScriptName()
		if err != nil {
			continue
		}
		s.Names = append(s.Names, scName)
		s.script = append(s.script, tmp_script)
	}
}
func (s *Source) Scan(sc Script, domain string) {
	defer s.wg.Done()
	name, err := sc.ScriptName()
	if err != nil {
		panic(err)
	}
	datas := sc.Scan(domain)
	for _, item := range datas {
		_, ok := s.Domains[item]
		if !ok {
			s.Domains[item] = void{}
			gologger.Printf("[%s] %s\n", aurora.Yellow(name).String(), item)
		}
	}
	<-s.limiter
}

func (s *Source) Feed(domain string) {
	s.wg.Wait()
	for _, sc := range s.script {
		s.wg.Add(1)
		s.limiter <- true
		go s.Scan(sc, domain)
	}
}

func (s *Source) Wait() {
	s.wg.Wait()
	for _, v := range s.script {
		v.Close()
	}
}
