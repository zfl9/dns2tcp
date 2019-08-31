# dns2tcp
一个 DNS 实用工具，用于将 DNS 查询从 UDP 模式转换为 TCP 模式。当然 pdnsd、dnsforwarder 也支持该功能，但是它们通常都有着较为繁杂的配置，而很多时候我们只是需要使用它们的 udp2tcp 功能而已，因此有了 `dns2tcp`。`dns2tcp` 设计的非常简洁以及易用，它不需要任何配置文件，直接在命令行参数中指定一个 **本地 UDP 监听地址** 以及一个 **远程 DNS 服务器地址**（该 DNS 服务器支持 TCP 查询）即可，没有任何多余的功能。

## 如何编译
`dns2tcp` 使用 [libuv](https://github.com/libuv/libuv) 作为网络库，因此请先安装 libuv 依赖库，比如使用 `yum`、`pacman` 等包管理器安装，然后编译 dns2tcp：
```bash
git clone https://github.com/zfl9/dns2tcp
cd dns2tcp
make && sudo make install
```
dns2tcp 默认安装到 `/usr/local/bin/dns2tcp`，可安装到其它目录，如 `make install DESTDIR=/opt/local/bin`。

如果你希望将 libuv 依赖库直接静态链接至 `dns2tcp` 可执行文件，那么可按照如下步骤进行：
```bash
cd /opt

# 获取 libuv 源码包
libuv_version="1.31.0"
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

// TODO
