# 2026-10-16 第三轮：RawStream 生命周期与小连接内存

基线 main `710d1d46c6c49cf14142c4ebb44d1f5db59184f7`。本轮重新读取代码和生产日志，不把前两轮已修复项列为新发现。确认同一生命周期缺陷的两种表现，另实现一个有本地测量依据的内存优化；未改变线上格式、密钥派生或拥塞控制。

## 1. RawStream 入口生命周期不一致

旧 Serve 在 reserveConnection/握手配额之后才 Add WaitGroup，且已 Accept 的握手没有 context 取消关闭钩子。Close 与 Add 之间没有共同的封闭锁；取消时可能等握手 deadline（2 秒），在不支持 deadline 的嵌入连接上还可能更久。HandleConnContext 虽有取消关闭钩子，却完全未登记 WaitGroup，Close 可以先于 handler/配额清理返回。

两个公开入口回归用 main 旧源码 overlay 各重复 3 次，均失败：

- `TestStreamShutdownInterruptsAcceptedHandshake`：真实 loopback TCP，确认 handler 已进入 Read，再 Close；旧版 1 秒内未退出，必须测试端关闭 peer 才退出。
- `TestStreamShutdownJoinsEmbeddedHandler`：net.Pipe，确认取消已关闭 socket，但用 barrier 保持 handler 尚未退出；旧版 Close 直接返回，未等待 handler 归还配额。

现在两个入口共用受 listenersMu 保护的接纳与 WaitGroup 登记，Close 在相同锁下封闭接纳。所有已接纳连接均挂取消关闭钩子；等待 handler 清理后才关闭 replay cache。连接/握手限制保持原值，不在每包热路径增加锁。补充并发接纳与关闭回归，检查配额及 semaphore 回零。

Add/Wait 是静态确认的并发窗口，本轮未复现其 panic；上述两种关闭行为错误则都有旧版失败、新版通过的直接证据。

此修复涉及 SDK StreamServer，包括 Xray 对其嵌入使用的关闭语义；不是已证明的 HKT 探测超时根因。

## 2. RawStream 按需记录缓冲

旧 FramedWriter 构造时立即分配 bulk flush 缓冲；FramedReader 同时预分配最大密文和明文缓冲，即使连接尚未传数据或仅有 SSH 小包。现在记录缓冲按实际首包/record 大小分配，bulk 时按需增长；既有 64 KiB bufio.Reader 不变。

`TestRawBufferLazyWireAndOwnership` 验证未 I/O 时记录缓冲为空、小包不保留 bulk 缓冲、小包到 2 MiB burst 的增长、与 eager 配置逐字节相同的密文和写出边界，以及认证 EOF 后的完整回读。既有部分读超时恢复、认证 EOF、scatter batch 等回归继续执行。

本机 Windows amd64 / Go 1.27.0 / GOMAXPROCS=4，三次 250ms 微基准：

| 本地构造分配 | 旧版 | 新版 |
| --- | --- | --- |
| 新建读写对象、尚无应用数据 | 314,368 B/op、14 allocs | 68,608 B/op、11 allocs |
| 同上，写 64 B 首包 | 314,368 B/op、14 allocs | 68,704 B/op、12 allocs |
| 同上，写 32 KiB 首包 | 约 314,375 B/op | 约 70,019 B/op |
| 同上，写 1 MiB 首包 | 约 315.6 KB/op | 约 80.6 KB/op |

构造基准包含两端 AEAD 对象和 bufio 等分配，不是进程 RSS，也不是完整握手或网络 I/O。空连接构造分配减少 240 KiB（约 78%）；已跑过大流量的连接仍会保留增长后的缓冲，未声称永久小内存。

热态写基准包含 AEAD 加密、io.Discard；分别验证串行和多条独立连接的 RunParallel。32 KiB 串行旧 8.58–9.54 us/op，新 7.29–8.40 us/op；1 MiB 串行旧 237–264 us/op，新 249–263 us/op；1 MiB 并行旧 59.0–60.8 us/op，新 60.2–62.5 us/op。存在调度/缓存噪声，未观察到明确的热态吞吐提升或显著退化，不把微基准 MB/s 换算为公网 Gbps。并行基准包含各 worker 一次预热分配，不能声称整项绝对零 B/op。

## 3. UDP 与生产只读复查

2026-10-16 约 11:49–11:52（UTC+8）重新检查五台可达业务机与 Realm：可读日志样本没有新 panic、OOM 或 FD 耗尽；5 秒低负载样本中 UDP receive/send buffer error 增量及 Xray socket drops 增量为零。部分 journal 缺失或被面板重复 warning 覆盖，不能外推全天无错误。这不是单/多线程饱和测试。

HKT SSH 经 DMIT 仍在 banner 阶段超时；路由器 11:40:34 记录 HKT HTTP HEAD 第二次响应超时，尚不能确认是健康检查时限、线路、节点还是代码根因。本轮未修改健康检查、Realm、路由、防火墙或生产进程。五台 Xray 及路由器运行二进制仍为较早的 `904d3ab` 对应哈希，而非本轮待发布代码。

本轮 UDP 路由、末批、读取租约、deadline、批处理和多逻辑流回归纳入验收；尚未发现足够证据支持新的 UDP 拥塞控制/GSO 架构改动，故不为“提速”盲目放大缓冲或更改丢包策略。WAN 单流/多流速率提升仍需受控隔离压测，不能从本轮低负载日志或 CPU/内存基准推导。

## 4. 验收状态

本地 stock/default 与 patched/http2legacy SDK internal/pkg 全量测试及 vet，Xray Chitanda/UDP Hub/配置与 vet，Mihomo config/outbound/sing_tun/SOCKS/tunnel 回归及 vet 全部通过。新 server/rawstream 用例在 stock 和 patched Xray 依赖下分别 30 轮通过；Xray 的 UDP 批处理边界、短缓冲/读取租约、deadline 及 data+EOF/error 末批回归额外 30 轮通过。

Xray、Mihomo（with_gvisor,http2legacy）的 Linux amd64/arm64 四个本地交叉编译通过。旧本地 fixture 使用 buildvcs=false 处理无关的目录所有者 stamping 限制，正式 Linux runner 的正常 VCS 构建另行通过。Python 27 项、四份工作流 YAML 与所有 shell 块语法、diff 空白检查均通过。

受验提交 `e7ffee21d786cdc69a44af8d54d3b675f279407a`，[Linux 验收 38848416505](https://github.com/chitanda-project/chitanda/actions/runs/38848416505) 四组全部成功，已读取日志核对新测试确有执行：

| 对象 | 通过内容 |
| --- | --- |
| stock SDK / Go 1.26.9 | default/http2legacy 全量 internal/pkg race；StreamShutdown、RawBufferLazy 各 30 轮 race；既有回归 |
| stock SDK / Go 1.27.2 | 同上，独立 Go 1.27 实现路径 |
| 注入 Xray / Go 1.26.9 / patched 依赖 | Chitanda/配置 race；新 server/rawstream 各 30 轮 race；五模式真实链式 TCP/UDP 10 轮及既有回归；Linux 构建 |
| 干净注入 Mihomo / Go 1.27.2 | config/outbound/sing_tun/SOCKS/tunnel race；关闭/输入、writer 30 轮 race；with_gvisor,http2legacy Linux 构建 |

最终追加仅为验收记录和 Release 展示文字，不更改已受验实现、测试或工作流执行命令。合入 main 后自动开始三项正式发布；未等待发布打包结束，也未部署生产。

审计/发布工作流显式恢复 vendor 内新 server/rawstream 测试并分别重复 30 次，静态合同检查恢复动作早于执行，避免依赖包“无测试文件”误判。文档中旧 250ms 强制截断、裸零长度 EOF 与现实现不符的描述一并纠正。

无协议兼容性变化；服务端关闭修复随 Xray/SDK 更新，RawStream 缓冲优化同时存在于客户端和服务端，可分别升级，不要求同步切换。代码推送、打包和实际部署是不同事项。
