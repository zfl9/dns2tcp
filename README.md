# dns2tcp

一个 DNS 实用工具，用于将 DNS 查询从 UDP 转为 TCP。当然 pdnsd、dnsforwarder 等工具也能实现该功能，但它们通常都有着较为繁杂的配置，而很多时候我们只是需要使用它们的 udp2tcp 功能而已，因此有了 `dns2tcp`。`dns2tcp` 设计的非常简洁以及易用，它不需要任何配置文件，直接在命令行参数中指定一个 **本地 UDP 监听地址** 以及一个 **远程 DNS 服务器地址**（该 DNS 服务器支持 TCP 查询）即可，没有任何多余的功能。

## 如何编译

> 为了方便使用，[releases](https://github.com/zfl9/dns2tcp/releases) 页面发布了静态链接(musl)二进制。

```bash
git clone https://github.com/zfl9/dns2tcp
cd dns2tcp
make && sudo make install
```

dns2tcp 默认安装到 `/usr/local/bin/dns2tcp`，可安装到其它目录，如 `make install DESTDIR=/opt/local/bin`。

交叉编译时只需指定 CC 变量，如 `make CC=aarch64-linux-gnu-gcc`（若报错，请先执行 `make clean`，然后再试）。

## 如何运行

```bash
# sh/bash 可以不加引号，zsh 等必须加引号，防止转义'#'字符
dns2tcp -L "127.0.0.1#5353" -R "8.8.8.8#53"
```

- `-L` 选项指定本地监听地址，该监听地址接受 UDP 协议的 DNS 查询。
- `-R` 选项指定远程 DNS 服务器地址，该 DNS 服务器应支持 TCP 查询。

## 全部参数

```bash
usage: dns2tcp <-L listen> <-R remote> [-s syncnt] [-6rafvVh]
 -L <ip#port>            udp listen address, this is required
 -R <ip#port>            tcp remote address, this is required
 -s <syncnt>             set TCP_SYNCNT(max) for remote socket
 -6                      enable IPV6_V6ONLY for listen socket
 -r                      enable SO_REUSEPORT for listen socket
 -a                      enable TCP_QUICKACK for remote socket
 -f                      enable TCP_FASTOPEN for remote socket
 -v                      print verbose log, default: <disabled>
 -V                      print version number of dns2tcp and exit
 -h                      print help information of dns2tcp and exit
bug report: https://github.com/zfl9/dns2tcp. email: zfl9.com@gmail.com
```

`-s`：对`TCP`套接字设置`TCP_SYNCNT`，其值将影响`TCP`连接超时时间。

`-6`：对`UDP`套接字设置`IPV6_V6ONLY`，建议始终启用，把 v4 和 v6 监听严格区分开。

`-r`：对`UDP`套接字设置`SO_REUSEPORT`，用于多进程负载均衡，Linux 3.9+ 开始可用。

`-a`：对`TCP`套接字设置`TCP_QUICKACK`，与`TCP_NODELAY`(默认启用)类似，详情可谷歌或man文档。

`-f`：对`TCP`套接字设置`TCP_FASTOPEN`，用于客户端 TFO，别忘了配置内核参数`net.ipv4.tcp_fastopen`。
