# dns2tcp

一个 DNS 实用工具，用于将 DNS 查询从 UDP 转为 TCP。

当然有很多 DNS 工具都可以实现这个功能，比如 pdnsd、dnsforwarder；但如果你只是想使用其 UDP 转 TCP 功能（比如配合 dnsmasq，将 dnsmasq 向上游发出的 DNS 查询从 UDP 转为 TCP），那么 dns2tcp 可能是更好的选择。

`dns2tcp` 设计的非常简洁以及易用，它不需要任何配置文件，在命令行参数中指定一个 **本地 UDP 监听地址** 以及一个 **远程 DNS 服务器地址**（该 DNS 服务器支持 TCP 查询）即可，没有任何多余功能。

## 如何编译

> 为了方便使用，[releases](https://github.com/zfl9/dns2tcp/releases) 页面发布了 linux 下常见架构的 musl 静态链接二进制。

```bash
git clone https://github.com/zfl9/dns2tcp
cd dns2tcp
make && sudo make install
```

dns2tcp 默认安装到 `/usr/local/bin/dns2tcp`，可安装到其它目录，如 `make install DESTDIR=/opt/local/bin`。

交叉编译时只需指定 CC 变量，如 `make CC=aarch64-linux-gnu-gcc`（若报错，请先执行 `make clean`，然后再试）。

## 如何运行

```bash
# sh/bash 可以不加引号，zsh 必须加引号，防止#被转义
# 好吧，这里我偷了下懒，端口号是必须指定的，即使是 53
# UPDATE: 从 v1.1.1 版本开始可以省略端口号，默认是 53
dns2tcp -L "127.0.0.1#5353" -R "8.8.8.8#53"

# 如果想在后台运行，可以这样做：
(dns2tcp -L "127.0.0.1#5353" -R "8.8.8.8#53" </dev/null &>>/var/log/dns2tcp.log &)
```

- `-L` 选项指定本地监听地址，该监听地址接受 UDP 协议的 DNS 查询。
- `-R` 选项指定远程 DNS 服务器地址，该 DNS 服务器应支持 TCP 查询。

## 小技巧

借助 iptables，将本机发往 8.8.8.8:53 的 UDP 查询请求，强行重定向至本机 dns2tcp 监听端口，这样就可以不用修改原有 dns 组件的配置，无感转换为 TCP 查询。还是上面那个例子，在启动 dns2tcp 之后，再执行如下 iptables 命令：

```bash
# 将目标地址为 8.8.8.8:53/udp 的包重定向至 dns2tcp 监听端口，实现透明 udp2tcp 转换
iptables -t nat -A OUTPUT -p udp -d 8.8.8.8 --dport 53 -j REDIRECT --to-ports 5353
```

你可以在本机使用 `dig @8.8.8.8 baidu.com` 测试，观察 dns2tcp 日志（带上 -v），就会发现走 TCP 出去了。

## 全部参数

```console
usage: dns2tcp <-L listen> <-R remote> [-s syncnt] [-6rvVh]
 -L <ip[#port]>          udp listen address, this is required
 -R <ip[#port]>          tcp remote address, this is required
 -s <syncnt>             set TCP_SYNCNT(max) for remote socket
 -6                      enable IPV6_V6ONLY for listen socket
 -r                      enable SO_REUSEPORT for listen socket
 -v                      print verbose log, default: <disabled>
 -V                      print version number of dns2tcp and exit
 -h                      print help information of dns2tcp and exit
bug report: https://github.com/zfl9/dns2tcp. email: zfl9.com@gmail.com
```

`-s`：对`TCP`套接字设置`TCP_SYNCNT`，其值将影响`TCP`连接超时时间。

`-6`：对`UDP`套接字设置`IPV6_V6ONLY`，建议始终启用，把 v4 和 v6 监听严格区分开。

`-r`：对`UDP`套接字设置`SO_REUSEPORT`，用于多进程负载均衡，Linux 3.9+ 开始可用。
