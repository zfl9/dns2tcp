# dns2tcp
一个 DNS 实用工具，用于将 DNS 查询从 UDP 模式转换为 TCP 模式。当然 pdnsd、dnsforwarder 也支持该功能，但是它们通常都有着较为繁杂的配置，而很多时候我们只是需要使用它们的 udp2tcp 功能而已，因此有了 `dns2tcp`。`dns2tcp` 设计的非常简洁以及易用，它不需要任何配置文件，直接在命令行参数中指定一个 **本地 UDP 监听地址** 以及一个 **远程 DNS 服务器地址**（该 DNS 服务器支持 TCP 查询）即可，没有任何多余的功能。

## 如何编译
**动态链接 libuv**
`dns2tcp` 使用 [libuv](https://github.com/libuv/libuv) 作为网络库，因此请先安装 libuv 依赖库（如 `yum` 安装），然后开始编译：
```bash
git clone https://github.com/zfl9/dns2tcp
cd dns2tcp
make && sudo make install
```
dns2tcp 默认安装到 `/usr/local/bin/dns2tcp`，可安装到其它目录，如 `make install DESTDIR=/opt/local/bin`。

**静态链接 libuv**
如果想将 [libuv](https://github.com/libuv/libuv) 依赖库静态链接到 `dns2tcp` 可执行文件中，可按照如下步骤进行编译（glibc 不建议静态链接）：
```bash
# 进入某个目录
cd /opt

# 获取 libuv 源码包
libuv_version="1.32.0" # 定义 libuv 版本号
wget https://github.com/libuv/libuv/archive/v$libuv_version.tar.gz -Olibuv-$libuv_version.tar.gz
tar xvf libuv-$libuv_version.tar.gz

# 进入源码目录，编译
cd libuv-$libuv_version
./autogen.sh
./configure --prefix=/opt/libuv --enable-shared=no --enable-static=yes CC="gcc -O3"
make && sudo make install
cd ..

# 获取 dns2tcp 源码
git clone https://github.com/zfl9/dns2tcp

# 进入源码目录，编译
cd dns2tcp
make INCLUDES="-I/opt/libuv/include" LDFLAGS="-L/opt/libuv/lib" && sudo make install
```
这种方式特别适用于交叉编译，因为编译出来的可执行文件不依赖任何第三方库，可直接拷贝到目标系统来运行。

## 如何运行
```bash
dns2tcp -L"127.0.0.1#5353" -R"8.8.8.8#53"
```
- `-L` 选项指定本地监听地址，该监听地址接受 UDP 形式的 DNS 查询。
- `-R` 选项指定远程 DNS 服务器地址，该 DNS 服务器应支持 TCP 查询。
- 该例子中，dns2tcp 会将从 `127.0.0.1#5353` 地址收到 dns query 转换为 tcp 形式的 dns query，然后与 `8.8.8.8#53` 服务器建立 TCP 连接，连接建立后，会将此 dns query 发送给 `8.8.8.8#53`，然后等待 `8.8.8.8#53` 的 dns reply，收到完整 packet 后，将其转换为 udp 形式的 dns reply，最后将其发送给与之关联的请求客户端，并释放 TCP 连接及相关数据。

Enjoy it!
