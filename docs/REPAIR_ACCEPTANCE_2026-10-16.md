# 2026-10-16 写队列清理与生产日志复查

基于 main `904d3abf9f1549cad96713df3b1f3c2be873b463`。本轮确认一个新的资源回收缺陷；未把性能架构待办、健康检查失败或无法连接的节点计为已修复问题。

## 确认缺陷及修复

`pkg/connio.Writer` 的写入调用超时后，已接纳的数据仍由 worker 持有，调用者可提交下一项到长度为 1 的队列。若前一项底层写入随后报错，或在此时 Close，worker 原来直接退出，下一项的 worker 引用及 64 KiB 池化缓冲不释放。Writer 若仍被引用，这块缓冲持续保留；并不是证明所有这些对象都永久逃逸 GC。

新增 `TestWriterShutdownReleasesQueuedRequest` 通过公开 API 构造阻塞写、两次真实写超时和排队项。未修复时底层错误、Close 两个子用例均失败：`queued=1 refs=1 buffer=true`。

修复区分“停止接纳/唤醒”与“清理结束”：worker 退出先关闭 stopping，唤醒可能仍持有提交 gate 的调用者，再取得 gate 清空队列、完成请求并归还租约，最后关闭 exited。与退出竞争的发送也在同一 gate 的清理范围内。取出请求后再次检查 Close，避免已经观察到关闭仍执行排队写。

- 不把完成信号提前当成清理结束；Close 等待回收完成。
- 不通过无限缓存、丢失引用计数或每次写入新增后台协程规避问题。
- 保留可恢复 deadline、已接纳字节计数、半关闭及固定队列上限。
- 补充仍在等待的排队调用者唤醒、并发 Close/提交（每轮 100 组、每组 4 个调用者）回归。

该适配器用于 H2 SDK 客户端和 Xray H3 虚拟入站写回。当前生产 stream/Plain-UDP 的主要数据路径不因此获得批量化或单流聚合。本轮不宣称修复了所有断线或公网性能问题。

## 本地验收

- stock/default SDK internal/pkg 全量测试通过。
- patched/http2legacy SDK internal/pkg 全量测试及 vet 通过。
- connio 全量 30 轮、新增 WriterShutdown 30 轮通过；并发提交回归不使用固定 sleep 排序。
- 本机 1400 字节 WriterWritePacket 微基准约 2.86–2.94 us/op，0 B/op、0 allocs/op。没有同窗口旧版对照，不据此声称速度提升；它也不是网络吞吐测试。

注入 Xray/Mihomo 接入验收、交叉编译及 Linux race 结果在最终合并前补录。审计工作流分别覆盖真实 stock 与 patched 依赖，恢复 vendor 中被 go mod vendor 删除的 connio 测试，避免“无测试文件”假通过。

## 生产只读检查

2026-10-16 约 09:15–09:25（UTC+8）：

- 五台可达业务机的运行中 Xray 哈希与 main `904d3ab` 发布元数据一致；路由器磁盘内核与运行中内核哈希也与该次 Mihomo 稳定版一致。未把版本字符串相同当成代码相同。
- 可读 journal/内核日志样本未发现 panic、OOM、文件句柄耗尽；有的节点没有可读 journal，不能等同于完整日志无异常。大量 `Access log is set to 'none'` 为面板告警，不是连接断开证据。
- 五台业务机各 5 秒被动窗口的 UDP RcvbufErrors/SndbufErrors 增量及 Xray 所持 UDP socket drops 均为零，队列快照为空；当时负载较低，不是饱和压测，不能推导高负载零丢包。
- HKT `42.3.69.88:30222` 直连、经 DMIT、经 IEPL SSH 转接均在 banner 握手阶段超时；本次无法读取其新日志，不推断它一定宕机或一定是协议故障。
- 路由器仍见 HKT 的 HTTP HEAD 第二次响应超时。实际运行配置的 HK/TW fallback 使用 HTTP 探测、1 秒间隔、1000 ms 超时、失败 1 次切换，和原始配置文件不同。该证据不足以证明业务连接同样中断，也不能归因于上述队列缺陷。
- IEPL Realm 可达、进程在运行；未修改它。低内存节点约 69 MiB 可用，仍不适合无预算扩大缓冲。

未导出或提交生产私钥、PSK、原始代理配置和日志。未部署、重启生产代理、修改防火墙、路由器、Realm 或健康检查参数。

## 更新范围

无线上格式、密钥派生、配置项变化，旧新版本可互通。H2 客户端和使用 H3 入站的 Xray 服务端分别更新才能取得各自路径的回收修复，不需要为协议兼容强制同步升级。推送/自动打包与实际安装是不同状态。
