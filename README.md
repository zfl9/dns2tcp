# dns2tcp
**简介**：一个 DNS 实用工具，用于将 DNS 查询从 UDP 模式转换为 TCP 模式。当然 pdnsd、dnsforwarder 也支持这一功能，但是 `dns2tcp` 实现的非常简洁和易用，不需要任何配置文件，直接命令行参数指定 **本地 UDP 监听地址** 以及 **远程 DNS 服务器地址**（该 DNS 服务器支持 TCP 查询）即可，没有任何多余的功能。

// TODO
