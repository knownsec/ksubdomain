ksubdomain是一款基于无状态子域名爆破工具，支持在Windows/Linux/Mac上使用，它会很快的进行DNS爆破，在Mac和Windows上理论最大发包速度在30w/s,linux上为160w/s的速度。
## 为什么这么快
ksubdomain的发送和接收是分离且不依赖系统，即使高并发发包，也不会占用系统描述符让系统网络阻塞。

可以用`--test`来测试本地最大发包数,但实际发包的多少和网络情况息息相关，ksubdomain将网络参数简化为了`-b`参数，输入你的网络下载速度如`-b 5m`，ksubdomain将会自动限制发包速度。
## 可靠性
类似masscan,这么大的发包速度意味着丢包也会非常严重，ksubdomain有丢包重发机制(这样意味着速度会减小，但比普通的DNS爆破快很多)，会保证每个包都收到DNS服务器的回复，漏报的可能性很小。

## 使用
从[releases](https://github.com/knownsec/ksubdomain/releases "releases")下载二进制文件。 

在linux下，还需要安装`libpcap-dev`,在Windows下需要安装`WinPcap`，mac下可以直接使用。
```

 _  __   _____       _         _                       _
| |/ /  / ____|     | |       | |                     (_)
| ' /  | (___  _   _| |__   __| | ___  _ __ ___   __ _ _ _ __
|  <    \___ \| | | | '_ \ / _| |/ _ \| '_   _ \ / _  | | '_ \
| . \   ____) | |_| | |_) | (_| | (_) | | | | | | (_| | | | | |
|_|\_\ |_____/ \__,_|_.__/ \__,_|\___/|_| |_| |_|\__,_|_|_| |_|

Usage of ./ksubdomain:
  -b string
        宽带的下行速度，可以5M,5K,5G (default "1M")
  -d string
        爆破域名
  -dl string
        从文件中读取爆破域名
  -e int
        默认网络设备ID,默认-1，如果有多个网络设备会在命令行中选择 (default -1)
  -f string
        字典路径,-d下文件为子域名字典，-verify下文件为需要验证的域名
  -l int
        爆破域名层级,默认爆破一级域名 (default 1)
  -o string
        输出文件路径
  -s string
        resolvers文件路径,默认使用内置DNS
  -silent
        使用后屏幕将不会输出结果
  -skip-wild
        跳过泛解析的域名
  -test
        测试本地最大发包数
  -ttl
        导出格式中包含TTL选项
  -verify
        验证模式

```
### 常用命令
```
使用内置字典爆破
ksubdomain -d seebug.org

使用字典爆破域名
ksubdomain -d seebug.org -f subdomains.dict

字典里都是域名，可使用验证模式
ksubdomain -f dns.txt -verify

爆破三级域名
ksubdomain -d seebug.org -l 2

通过管道爆破
echo "seebug.org"|ksubdomain

通过管道验证域名
echo "paper.seebug.org"|ksubdomain -verify
```
[![asciicast](https://asciinema.org/a/356138.svg)](https://asciinema.org/a/356138)
## 管道操作
借助知名的`subfinder`，`httpx`等工具，可以用管道结合在一起配合工作。
```bash
./subfinder -d baidu.com -silent|./ksubdomain -verify -silent|./httpx -title -content-length -status-code
```
- subfinder 通过各种搜索引擎获取域名
- ksubdomain 验证域名
- httpx http请求获得数据,验证存活
![image-20200902160128305](./images/image-20200902160128305.png)

## 编译
因为pcap包的特殊性，无法交叉编译，只能每个系统编译每个文件。
```bash
git clone https://github.com/knownsec/ksubdomain
cd ksubdomain
go mod download
cd cmd
go build ksubdomain.go
```
## 参考
- 从 Masscan, Zmap 源码分析到开发实践 <https://paper.seebug.org/1052/>