# 2026-10-16 写队列清理、并发接纳与生产日志复查

基于 main `904d3abf9f1549cad96713df3b1f3c2be873b463`。本轮确认一个资源回收缺陷和一个并发配额缺陷；未把性能架构待办、健康检查失败或无法连接的节点计为已修复问题。

## 确认缺陷及修复

`pkg/connio.Writer` 的写入调用超时后，已接纳的数据仍由 worker 持有，调用者可提交下一项到长度为 1 的队列。若前一项底层写入随后报错，或在此时 Close，worker 原来直接退出，下一项的 worker 引用及 64 KiB 池化缓冲不释放。Writer 若仍被引用，这块缓冲持续保留；并不是证明所有这些对象都永久逃逸 GC。

新增 `TestWriterShutdownReleasesQueuedRequest` 通过公开 API 构造阻塞写、两次真实写超时和排队项。未修复时底层错误、Close 两个子用例均失败：`queued=1 refs=1 buffer=true`。

修复区分“停止接纳/唤醒”与“清理结束”：worker 退出先关闭 stopping，唤醒可能仍持有提交 gate 的调用者，再取得 gate 清空队列、完成请求并归还租约，最后关闭 exited。与退出竞争的发送也在同一 gate 的清理范围内。取出请求后再次检查 Close，避免已经观察到关闭仍执行排队写。

- 不把完成信号提前当成清理结束；Close 等待回收完成。
- 不通过无限缓存、丢失引用计数或每次写入新增后台协程规避问题。
- 保留可恢复 deadline、已接纳字节计数、半关闭及固定队列上限。
- 补充仍在等待的排队调用者唤醒、并发 Close/提交（每轮 100 组、每组 4 个调用者）回归。

该适配器用于 H2 SDK 客户端和 Xray H3 虚拟入站写回。当前生产 stream/Plain-UDP 的主要数据路径不因此获得批量化或单流聚合。本轮不宣称修复了所有断线或公网性能问题。

## RawStream 并发接纳限额

原服务端先 Load 检查 activeConns，再独立 Add。两个并发 HandleConnContext 或多个 Serve listener 可以同时通过同一个限额检查。新增测试把已接纳握手保持阻塞，等 64 个调用全部接纳或拒绝后再释放，测量的是同时接纳数，不是累计建连次数；旧版在第 42 组复现配置 limit=1 却同时放行 2 个握手。

现在通过 CAS 原子预留连接数，独立的 Serve 和嵌入式 HandleConnContext 共用同一入口，握手池拒绝时回滚，已关闭的服务器拒绝预留。maxConns 使用原子值，保留默认 10000 与非正数不限制的既有语义，不自动关闭存量连接。没有增加每包锁或全局代理转发锁。

新增并发接纳、握手拒绝回滚、关闭拒绝、0/负数/正数限额用例，30 轮通过。该竞态不是无限制越限：原有握手池仍有界；不能据此宣称发现了可无限放大资源占用的漏洞。

## 本地验收

- stock/default SDK internal/pkg 全量测试及 vet 通过。
- patched/http2legacy SDK internal/pkg 全量测试及 vet 通过。
- connio 全量 30 轮、新增 WriterShutdown 30 轮通过；并发提交回归不使用固定 sleep 排序。
- 最终 WriterShutdown / StreamAdmission 定向各 100 轮通过。注入 Xray 的 Chitanda/UDP Hub 全套、配置回归及 vet，Mihomo config/outbound/sing_tun/SOCKS/tunnel 定向回归及 vet 均通过。
- Xray 和带 with_gvisor,http2legacy 的 Mihomo，Linux amd64/arm64 共四个交叉编译通过。旧本地 fixture 的 VCS 安全目录检查阻止自动 stamping，使用 buildvcs=false 只构建本地验收产物；不是正式发布构建失败。ARM 未执行目标机运行压测。
- Python 26 项回归、四个工作流 YAML 和全部 shell 块语法、git diff 空白检查通过。
- 本机 1400 字节 WriterWritePacket 微基准首轮约 2.86–2.94 us/op。后续旧版 overlay 五次约 2.97–3.21 us/op，新版五次约 3.06–3.37 us/op；均 0 B/op、0 allocs/op。存在并行编译/调度干扰，不据此宣称速度提升或统计上无退化；它也不是网络吞吐测试。

另将 Writer 微基准限制 GOMAXPROCS=1 重复五次：旧版约 1.95–2.33 us/op，新版约 1.94–1.99 us/op，仍均零分配。结果区间重叠，不把该局部基准换算成公网单/多流速率提升。

## Linux 最终验收

受验实现/测试/工作流提交：`54a7eda39204606d5686334b5e28a49aecaa7b5e`。修复代码分别在 `8ba55f3`、`ee27a3b`；最终提交仅补充文档及 release 展示文字，不改受验实现和执行命令。

[最终 Linux CI](https://github.com/chitanda-project/chitanda/actions/runs/38835896183) 四组全部成功：

| 对象 | 通过内容 |
| --- | --- |
| stock SDK / Go 1.26.9 | default/http2legacy 两套 internal/pkg 全量 race；写队列、并发接纳、H3 生命周期分别 30 轮 race |
| stock SDK / Go 1.27.2 | 同上，独立 Go 1.27 路径 |
| 注入 Xray / patched 依赖 | Chitanda/配置 race；写队列与并发接纳各 30 轮 race；H3 生命周期 30 轮、五模式真实链式 10 轮 race；Linux 构建 |
| 干净注入 Mihomo | config/outbound/sing_tun/SOCKS/tunnel 接入 race；关闭/输入验证及写队列各 30 轮 race；with_gvisor,http2legacy Linux 构建 |

审计工作流分别覆盖真实 stock 与 patched 依赖，恢复 vendor 中被 go mod vendor 删除的 connio/server 测试，避免“无测试文件”假通过。已核对 Xray vendor 中 connio/server 均实际执行并输出 ok，不是只恢复文件名或跳过失败。

## 验收中发现的 CI 稳定性问题

第二轮审计 `38835536099` 的 Xray job 在执行源码测试之前，上游 releases/latest 的四次匿名 API 请求均返回 HTTP 403。日志没有响应体，不能断定具体是主限流还是其他 403 原因，也不能把该 job 计为代码验收通过。

审计和三个发布工作流的固定 GitHub 上游元数据查询统一改用工作流自身的 github.token 认证，不使用或上传生产凭据，不放宽 audit 的 contents:read 权限。新增静态工作流合同回归，检查五处查询均传递认证，并确认 vendor 测试恢复先于实际执行。最终验收必须在修正后的工作流重新运行。

## 生产只读检查

2026-10-16 约 09:15–09:25（UTC+8）：

- 五台可达业务机的运行中 Xray 哈希与 main `904d3ab` 发布元数据一致；路由器磁盘内核与运行中内核哈希也与该次 Mihomo 稳定版一致。未把版本字符串相同当成代码相同。
- 可读 journal/内核日志样本未发现 panic、OOM、文件句柄耗尽；有的节点没有可读 journal，不能等同于完整日志无异常。大量 `Access log is set to 'none'` 为面板告警，不是连接断开证据。
- 五台业务机各 5 秒被动窗口的 UDP RcvbufErrors/SndbufErrors 增量及 Xray 所持 UDP socket drops 均为零，队列快照为空；当时负载较低，不是饱和压测，不能推导高负载零丢包。
- HKT SSH 直连、经 DMIT、经 IEPL 转接均在 banner 握手阶段超时；本次无法读取其新日志，不推断它一定宕机或一定是协议故障。
- 路由器仍见 HKT 的 HTTP HEAD 第二次响应超时。实际运行配置的 HK/TW fallback 使用 HTTP 探测、1 秒间隔、1000 ms 超时、失败 1 次切换，和原始配置文件不同。该证据不足以证明业务连接同样中断，也不能归因于上述队列缺陷。
- IEPL Realm 可达、进程在运行；未修改它。低内存节点约 69 MiB 可用，仍不适合无预算扩大缓冲。

未导出或提交生产私钥、PSK、原始代理配置和日志。未部署、重启生产代理、修改防火墙、路由器、Realm 或健康检查参数。

## 更新范围

无线上格式、密钥派生、配置项变化，旧新版本可互通。H2 客户端和使用 H3 入站的 Xray 服务端分别更新才能取得各自路径的回收修复，stream 服务端更新取得并发限额修复；不需要为协议兼容强制同步升级。推送/自动打包与实际安装是不同状态。
