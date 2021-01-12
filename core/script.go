package core

import (
	"crypto/tls"
	"errors"
	lua "github.com/yuin/gopher-lua"
	"io"
	"io/ioutil"
	luajson "layeh.com/gopher-json"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
	"time"
)

const (
	// UserAgent is the default user agent used by Amass during HTTP requests.
	UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36"

	// Accept is the default HTTP Accept header value used by Amass.
	Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"

	// AcceptLang is the default HTTP Accept-Language header value used by Amass.
	AcceptLang = "en-US,en;q=0.8"

	defaultTLSConnectTimeout = 3 * time.Second
	defaultHandshakeDeadline = 5 * time.Second

	SUBRE = "(([a-zA-Z0-9]{1}|[_a-zA-Z0-9]{1}[_a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+"
)

func getStringField(L *lua.LState, t lua.LValue, key string) (string, bool) {
	lv := L.GetField(t, key)
	if s, ok := lv.(lua.LString); ok {
		return string(s), true
	}
	return "", false
}

// SubdomainRegexString returns a regular expression string that matchs
// subdomain names ending with the domain provided by the parameter.
func SubdomainRegexString(domain string) string {
	// Change all the periods into literal periods for the regex
	return SUBRE + strings.Replace(domain, ".", "[.]", -1)
}
func SubdomainRegex(domain string) *regexp.Regexp {
	return regexp.MustCompile(SubdomainRegexString(domain))
}

// AnySubdomainRegex returns a Regexp object initialized to match any DNS subdomain name.
func AnySubdomainRegex() *regexp.Regexp {
	return regexp.MustCompile(AnySubdomainRegexString())
}

// AnySubdomainRegexString returns a regular expression string to match any DNS subdomain name.
func AnySubdomainRegexString() string {
	return SUBRE + "[a-zA-Z]{2,61}"
}

// Wrapper so that scripts can scrape the contents of a GET request for subdomain names in scope.
func scrape(L *lua.LState) int {
	opt := L.CheckTable(1)
	//
	var body io.Reader
	if method, ok := getStringField(L, opt, "method"); ok && (method == "POST" || method == "post") {
		if data, ok := getStringField(L, opt, "data"); ok {
			body = strings.NewReader(data)
		}
	}
	//
	url, found := getStringField(L, opt, "url")
	if !found {
		L.Push(lua.LNil)
		L.Push(lua.LString("No URL found in the parameters"))
		return 2
	}
	//
	headers := make(map[string]string)
	lv := L.GetField(opt, "headers")
	if tbl, ok := lv.(*lua.LTable); ok {
		tbl.ForEach(func(k, v lua.LValue) {
			headers[k.String()] = v.String()
		})
	}
	//
	id, _ := getStringField(L, opt, "id")
	pass, _ := getStringField(L, opt, "pass")
	//
	page, err := RequestWebPage(url, body, headers, id, pass)

	if err != nil {
		L.Push(lua.LNil)
		return 1
	}
	//
	domain := L.ToString(2)
	var res []string
	if domain == "" {
		for _, name := range AnySubdomainRegex().FindAllString(page, -1) {
			res = append(res, name)
		}
	} else {
		// SUBRE is a regular expression that will match on all subdomains once the domain is appended.
		for _, name := range SubdomainRegex(domain).FindAllString(page, -1) {
			res = append(res, name)
		}
	}
	t := L.NewTable()
	for _, v := range res {
		t.Append(lua.LString(v))
	}
	// 将返货结果堆栈
	L.Push(t)
	return 1
}

func RequestWebPage(urlstring string, body io.Reader, hvals map[string]string, uid, secret string) (string, error) {
	method := "GET"
	if body != nil {
		method = "POST"
	}
	req, err := http.NewRequest(method, urlstring, body)
	if err != nil {
		return "", err
	}
	if uid != "" && secret != "" {
		req.SetBasicAuth(uid, secret)
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", Accept)
	req.Header.Set("Accept-Language", AcceptLang)

	for k, v := range hvals {
		req.Header.Set(k, v)
	}

	jar, _ := cookiejar.New(nil)
	var DefaultClient *http.Client
	DefaultClient = &http.Client{
		Timeout: time.Second * 180, // Google's timeout
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          200,
			MaxConnsPerHost:       50,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   20 * time.Second,
			ExpectContinueTimeout: 20 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		},
		Jar: jar,
	}

	resp, err := DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		err = errors.New(resp.Status)
	}
	return string(in), err
}

func request(L *lua.LState) int {
	opt := L.CheckTable(1)
	//
	var body io.Reader
	if method, ok := getStringField(L, opt, "method"); ok && (method == "POST" || method == "post") {
		if data, ok := getStringField(L, opt, "data"); ok {
			body = strings.NewReader(data)
		}
	}
	//
	url, found := getStringField(L, opt, "url")
	if !found {
		L.Push(lua.LNil)
		L.Push(lua.LString("No URL found in the parameters"))
		return 2
	}
	//
	headers := make(map[string]string)
	lv := L.GetField(opt, "headers")
	if tbl, ok := lv.(*lua.LTable); ok {
		tbl.ForEach(func(k, v lua.LValue) {
			headers[k.String()] = v.String()
		})
	}
	//
	id, _ := getStringField(L, opt, "id")
	pass, _ := getStringField(L, opt, "pass")
	//
	page, err := RequestWebPage(url, body, headers, id, pass)

	if err != nil {
		L.Push(lua.LString(page))
		L.Push(lua.LString(err.Error()))
		return 2
	}
	//
	L.Push(lua.LString(page))
	L.Push(lua.LNil)
	return 2
}

type Script struct {
	luaState *lua.LState
}

func (s *Script) newLuaState(script string) {
	L := lua.NewState() // 创建一个lua解释器实例
	//defer L.Close()
	L.PreloadModule("json", luajson.Loader)
	L.SetGlobal("request", L.NewFunction(request))
	L.SetGlobal("scrape", L.NewFunction(scrape))
	if err := L.DoString(script); err != nil {
		panic(err)
	}
	s.luaState = L
}
func (s *Script) Close() {
	s.luaState.Close()
}
func (s *Script) Scan(domain string) []string {
	L := s.luaState
	err := L.CallByParam(lua.P{
		Fn:      L.GetGlobal("vertical"),
		NRet:    1,
		Protect: true,
	}, lua.LString(domain))
	if err != nil {
		panic(err)
	}
	ret := L.Get(-1)
	L.Pop(1)
	var q []string = []string{}
	switch ret.Type() {
	case lua.LTNil:
	case lua.LTString:
		q = append(q, ret.String())
	case lua.LTTable:
		res, ok := ret.(*lua.LTable)
		if ok {
			res.ForEach(func(_ lua.LValue, value lua.LValue) {
				q = append(q, value.String())
			})
		}
	}
	return q
}

// Acquires the script name of the script by accessing the global variable.
func (s *Script) ScriptName() (string, error) {
	L := s.luaState

	lv := L.GetGlobal("name")
	if lv.Type() == lua.LTNil {
		return "", errors.New("Script does not contain the 'name' global")
	}

	if str, ok := lv.(lua.LString); ok {
		return string(str), nil
	}

	return "", errors.New("The script global 'name' is not a string")
}
