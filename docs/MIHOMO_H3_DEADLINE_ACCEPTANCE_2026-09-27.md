# Mihomo H3 写入截止时间补丁验收（2026-09-27）

## 范围

Mihomo Stable `v1.19.31`（`ab405bad`）与 Alpha（`f103639c`）均将 Chitanda SDK 使用的 `github.com/quic-go/quic-go@v0.61.0` 指向本仓库已验收的补丁源码。Mihomo 自身使用的 `github.com/metacubex/quic-go` 不受此替换影响。构建脚本在标准 quic-go 版本改变、已有其他 replace 或补丁标记缺失时拒绝继续。

## 验收结果

- 两分支注入后，`./config` 和 `./adapter/outbound` 的 Chitanda 定向测试及 Linux `-race` 均通过；测试还在编译期检查 HTTP/3 和 QUIC 的可取消 Datagram 写入 API。
- Stable、Alpha 的 Linux ARM64 二进制均构建成功；构建元数据确认标准 quic-go 解析到 `.chitanda-quic-go`。
- 测试机 `168.138.209.1` 上的 Mihomo 客户端通过 H3 连接 `170.9.59.149` 上的隔离 Xray 服务端。两个版本的 HTTP 请求均返回 200，SOCKS5 UDP 回显均为 100/100。
- 同一路径的 SOCKS5 UDP 定速发送、服务端 UDP sink 计数如下。每轮 10 秒、1200 字节负载；百分比是客户端发出数与 sink 收到数之差，并非公网链路丢包定位结论。

| 构建 | 速率 | 发出 | 收到 | 差额 |
| --- | ---: | ---: | ---: | ---: |
| Stable 未打补丁基线 | 20 Mbps | 20,835 | 20,168 | 3.20% |
| Alpha 补丁版 | 20 Mbps | 20,835 | 20,530 | 1.46% |
| Stable 未打补丁基线 | 50 Mbps | 52,084 | 49,514 | 4.93% |
| Stable 补丁版 | 50 Mbps | 52,084 | 51,127 | 1.84% |
| Alpha 补丁版 | 50 Mbps | 52,084 | 51,129 | 1.83% |
| Stable 补丁版 | 100 Mbps | 104,167 | 102,127 | 1.96% |

结论：补丁已经进入两种 Mihomo 构建及真实 H3 数据路径；该测试未见吞吐回退，20/50 Mbps 的收发数差低于未打补丁基线。仍有约 1.5%–2% 的端到端 UDP 差额，本次测试未定位其发生位置，也不能据此宣称游戏断联问题已经解决。测试仅使用隔离端口，结束后停止了测试进程；未替换线上服务。
