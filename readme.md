## TOdo
1. [x] 自动获取本地设备，ip，device，源mac地址，目的mac地址
2. [x] 速度控制
3. [ ] 动态选择DNS(DNS成功率)
4. [x] 用src port验证属于哪类dns 本地状态表
5. [x] 测试本地最大发包量
6. [x] 从stdin读取
7. [x] dns reslover 命令行读取
8. [x] 保存文件

## 安装
### linux 
libpcap-dev
### Windows
安装WinPcap

## Readme
ksubdomain是一款基于无状态的子域名爆破工具，支持在Windows/Linux/Mac上使用，它会很快的进行DNS爆破，在Mac和Windows上理论最大发包速度在30w/s,linux上为160w/s的速度。
这么大的发包速度意味着丢包也会非常严重，ksubdomain有丢包重发机制，会保证每个包都收到DNS服务器的回复,ksubdomain有动态DNS选择器，在爆破时会优先选择成功率高的DNS。
可以用`--test`来测试本地最大发包数
发包的多少和网络情况也息息相关，ksubdomain将网络参数简化为了`-b`参数，输入你的网络下载速度如`-b 5m`，ksubdomain将会自动限制发包速度。

ksubdomain的发送和接收是分离且不依赖系统，即使高并发发包，也不会占用系统描述符让系统网络阻塞。