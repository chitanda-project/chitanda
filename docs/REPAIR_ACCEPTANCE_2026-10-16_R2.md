# 2026-10-16 第二轮：TCP/UDP 缓冲与关闭复查

基于 main `1f0ef7fb44d33a22fc40d1e5489a0cb7ecbede1c`。本轮确认一个独立 UDP 服务关闭竞态，并实现三个有局部测量依据的缓冲优化；不把性能待办或 HKT 健康检查超时计为已修复故障。

## 1. 独立 Plain-UDP 的生产结束与排空定序

旧接收循环先读包/解密，再发送到 worker channel；worker 一看到 ctx.Done 就把当时的队列排空并退出。如果取消恰好发生在解密期间，worker 退出后接收循环仍可成功入队，留下一个永远无人处理的任务、64 KiB scratch 和非零 inFlightMem。

`TestPlainUDPShutdownDrainsLateDecodedPacket` 使用真实 loopback UDP、合法密文、经过构造器校验的 128 用户配置（现有限额），在读包预留后取消。旧源码 overlay 连续 10 次失败，均为 `queued=1 memory=65536`。没有篡改 transport 名称、关闭校验或给生产路径加调度钩子。

现在接收循环是任务 channel 的唯一生产者，也负责在退出时关闭它们。worker 按 range 排空；取消后的任务只归还预算，不再执行转发。关闭等待 producer、worker 和 upstream reader 退出，不允许生产者在消费者排空后再遗留任务。

这是 SDK 独立 PlainUDPServer / StreamServer.AttachUDP 路径的缺陷，**不是证明 Xray 的 UDP Hub 也走这个 worker 池**，也未证明它是生产 HKT 探测超时的根因。

## 2. 独立 UDP 队列减少 scratch 持有

Codec.DecodePacket 已返回独立拥有的 payload，旧 udpTask 仍无用途地把接收用 64 KiB 缓冲持有到处理结束。现在每个接收循环只借用一块 scratch；入队任务仅持有解码后的 payload/地址。

- 不放大队列数量和默认预算，仍在解密/复制前预留，拒绝、消费、取消及关闭均归还。
- 用密文长度向上取二次幂，再加 metadata 余量；不是按 make 的逻辑 cap 直接冒充实际分配占用。该模型保守计入 backing 分配粒度。
- 真实 32 包、每包 1200 字节，在目标解析被阻塞时验证全部排队：旧 raw-buffer 预留 2,097,152 B，新预留 73,728 B（72 KiB）。释放解析后逐包验证内容和次序。
- 这是队列预留/持有模型，不是进程 RSS 测量。解密 scratch、channel 固定容量、会话表、socket buffer 等不是整个进程都被这一个 64 MiB 预算覆盖。

## 3. Xray UDP 读取租约

packetLinkConn 原来从 buf.Reader 获取已拥有的 Buffer，复制到新切片后立即 Release；connio 再将该切片复制给消费者。改为 NewOwnedReader，直接租用原 Buffer，只在消费、短缓冲丢弃或关闭时 Release。

保留每 Buffer 一个 UDP 包、域名来源地址、空 UDP 报文、同次 data+EOF/error 的末批语义和可恢复 deadline。不会把上游 Buffer 提前回收到池后继续读它，也不会把内部池化切片返回给公开 ReadFrom 的调用者。

回归覆盖真实底层内存复用、归还时机、短缓冲、9000 字节报文、空包、末批 EOF/异常、deadline 与关闭排空。测试 reader 在 Close 时归还尚未转交的 Buffer，以区分 reader 自有资源与已交给适配器的租约。

该改动适用于 Xray 原生 UDP 路由和通过 Xray 链式 PacketConn 的收包路径，包含当前 stream 部署涉及的 UDP 路径；不等于增加了 Plain-UDP GSO/批量发送。

## 4. H2/H3/auto TCP DATA 帧缓冲

StreamWriter 原来每帧 make(header+payload)，大流量时反复分配/复制最高约 256 KiB。现在在一次 Write 内借用 256 B、4 KiB、32 KiB 或既有 256 KiB 分级池，调用结束即归还；空闲连接不分别持有 bulk scratch。

保留私有帧格式、DATA 切分上限、写入计数、半关闭和部分错误后的终止行为。没有等待未来写入来凑批，没有新增每帧 goroutine，也没有改变拥塞控制或线上密钥。

此处作用于协商私有帧的 H2/H3/auto TCP；**当前生产均为 stream 的节点不会因此获得 RawStream TCP 加速**。RawStream 自有 AEAD 分帧与 ramp-up 策略未修改。

## 5. 串行/并行局部基准

环境：Windows amd64、Hygon C86-3G、Go 1.27.0，GOMAXPROCS=4；每项 3 次、250–300 ms。并行项为多条独立逻辑连接，不把一个 TCP 流拆成多路径。旧版来自 `1f0ef7f`，通过源码 overlay 对照；帧层旧版在修改前运行相同 benchmark。

| 局部路径 | 旧版时间 | 新版时间 | 分配变化 |
| --- | --- | --- | --- |
| TCP 帧 32 KiB 串行 | 8.39–10.14 us/op | 1.18–1.18 us/op | 40,960 B/帧 → 稳态 0 B/帧 |
| TCP 帧 32 KiB 并行 | 5.43–6.66 us/op | 0.307–0.324 us/op | 同上 |
| Xray UDP 1200 B 串行 | 3.22–3.51 us/op | 1.80–2.25 us/op | 1361 → 96 B/包 |
| Xray UDP 1200 B 并行 | 0.980–1.019 us/op | 0.304–0.312 us/op | 同上 |
| Xray UDP 9000 B 串行 | 5.52–6.23 us/op | 2.86–3.01 us/op | 约 9640 → 96–98 B/包 |
| Xray UDP 9000 B 并行 | 3.33–3.48 us/op | 0.465–0.499 us/op | 同上 |

UDP 基准分配次数仍为 4 allocs/op，减少的是载荷大小的分配字节和一次复制，不能写成“零分配 UDP”。TCP 池在冷启动/GC 清空后仍可能重新分配，表中是稳态数据。

TCP 底层使用 io.Discard，UDP 使用有真实 Buffer 分配/释放和 reader worker 的本地适配器。它们用于隔离 CPU、复制和 GC 成本，**不是端到端加密、网络带宽、WAN 丢包、尾延迟或 Linux/ARM 性能结论**。不得将 MB/s 换算成宣称已跑满某台公网机器的 Gbps。

## 6. 本地验收与 Linux 门禁

SDK stock/default、patched/http2legacy 两套 internal/pkg 全量测试及 vet，Xray Chitanda/UDP Hub/配置回归及 vet，Mihomo config/outbound/sing_tun/SOCKS/tunnel 回归及 vet 已通过。新关闭/预算、帧格式/并发、Xray 读取租约用例分别重复验证，patched Xray vendor 中的新 SDK 用例各 30 轮通过。

Xray 与带 with_gvisor,http2legacy 的 Mihomo，Linux amd64/arm64 四个交叉编译均通过。本地旧 fixture 使用 buildvcs=false 避免无关的 VCS 目录所有者 stamping 错误；正式 runner 的正常 VCS 构建单独通过。未声称在 ARM 目标机执行了性能压测。Python 27 项、四个工作流 YAML/shell 块语法与 diff 空白检查通过。

受验源码与门禁提交：`263e0c002265a1501a99ec5136e84c0932625cbe`。[Linux 最终验收](https://github.com/chitanda-project/chitanda/actions/runs/38846499581) 四组全部成功：

| 对象 | 通过内容 |
| --- | --- |
| stock SDK / Go 1.26.9 | default/http2legacy 全套 internal/pkg race；新关闭/内存预算与帧复用分别 30 轮 race；既有生命周期回归 |
| stock SDK / Go 1.27.2 | 同上，独立 Go 1.27 路径 |
| 注入 Xray / patched 依赖 | Chitanda/配置 race；新 SDK server/frame 各 30 轮、Xray PacketReadLease 30 轮 race；五模式真实链式 10 轮及既有关闭回归；Linux 构建 |
| 干净注入 Mihomo | config/outbound/sing_tun/SOCKS/tunnel race；关闭/输入及 writer 30 轮 race；with_gvisor,http2legacy Linux 构建 |

最后提交仅补充验收记录和 release 展示文字，不改已受验的实现、测试或执行命令。推送 main 启动正式多架构发布；其完成状态与本轮合并前验收、实际设备安装是不同事项。

发布与审计门禁恢复 vendor 内被 go mod vendor 省略的 server/frame 测试，再执行 30 轮 race；另对真实 Xray PacketReadLease 做 30 轮 race。静态工作流合同检查这些用例确实恢复且执行，不用“无测试文件”冒充通过。

## 7. 生产只读复查与仍未完成项

2026-10-16 约 11:17–11:40（UTC+8）：五台可达业务机没有在可读日志样本发现 panic、OOM、FD 耗尽；低负载 5 秒窗口 UDP RcvbufErrors/SndbufErrors 增量和 Xray 所持 socket drops 均为零，队列为空。这不是饱和压测，有的节点缺少 journal，不能推导所有时段无异常。

五台运行中 Xray 仍为 `13dc4df5…`，路由器磁盘与运行中内核仍为 `3efffde4…`，对应较早的 `904d3ab` 产物；最新 `1f0ef7f` 发布元数据的对应哈希不同。代码发布成功不等于节点已升级，本轮不替用户部署。

HKT 经 DMIT 和经路由器 SSH 转接仍在 banner 握手阶段超时，无法读取其新日志。路由器 10:50 仍见 HKT 的 HTTP HEAD 第二次响应超时，实际运行的 HK/TW fallback 仍为 HTTP URL、1 秒间隔、1000 ms 超时、失败 1 次切换。健康检查失败不能单独证明业务连接断开，尚未确认该异常的完整根因。

后续性能候选但本轮未擅改：

- RawStream 首段小 record 的立即 flush 有 syscall 合并空间，须同时比较首字节和尾延迟，不能只改 bulk 基准。
- stream/H1 原生 UDP 的客户端/转发链批量发送仍未形成完整 GSO 路径，不能把 H3 批处理收益套用到它。
- 慢 DNS/目标 I/O 对串行原生 UDP 接收分发仍可能造成队首阻塞；分片 worker 需要独立的队列预算、顺序和用户隔离设计。
- 低内存节点不适合盲目增加每目标 socket buffer 或池上限；共享单队列 virtio、CPU steal 和网络丢包仍须受控目标机压测区分。

未上传生产私钥、PSK、原始配置或原始日志；未部署/重启代理，未修改路由器、IEPL/Realm、防火墙或健康检查参数。无线上格式和密钥派生变化，可分步更新各受影响路径，不要求为兼容性强制双端同时更新。
