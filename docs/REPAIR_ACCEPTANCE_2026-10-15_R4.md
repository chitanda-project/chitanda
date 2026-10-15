# 2026-10-15 链式载体与 Mihomo 生命周期修复

基于 main `94594679f03fa8ded74a19033e3ff4fd66c83e77`。本轮修复复查确认的三项代码缺陷，未把吞吐架构待办或生产健康检查参数算作已完成。

## 1. H3 物理载体的嵌入拨号上下文

原 `ensureConnection` 在 QUIC DialEarly 成功后无条件取消 dialCtx。Xray 的 proxySettings 使用这个上下文驱动实际转发任务，因此建连成功不代表可以取消它。

- 为每个物理载体保留 context values，并分离拨号调用者与 manager 生命周期。建连期间仍响应调用者取消；成功交接后移除调用者取消钩子，不让首个逻辑流结束或预热超时上下文的取消终止共享载体。
- 物理 QUIC 关闭、manager 关闭、失效替换或空闲扩池回收时，取消所保留的上下文并关闭 owned PacketConn；显式关闭和物理断开共享一次性释放，避免重复 Close。
- QUIC 关闭回调只捕获不可变局部状态，避免回调即时执行与连接发布竞争。不在 manager 锁内执行外部 socket Close，不增加每包协程或取消钩子。
- 晚返回、取消后返回及同时返回 socket+error 的拨号结果均清理；不通过删 cancel 或无限延长上下文解决问题。完全不响应取消的外部 resolver/dialer 仍无法由 SDK 强制终止。
- 保留上轮 H3 PacketConn 接收取消修复：物理载体的上下文与逻辑 UDP 接收上下文是两层，不互相替代。

正式 SDK 回归覆盖保留路由值、dial-only 取消、关闭单关联不杀死载体、manager/物理关闭、一次性 socket 释放、扩池预热交接/回收、晚返回 socket 和待决握手取消。

## 2. Mihomo 适配器关闭后不可复活

原 Close 将 client 置 nil，getClient 又会重新初始化连接池、探测器/扩池任务。现在 initMu 保护永久 closed 状态，包括首次初始化前已关闭的对象；公开 TCP/UDP 拨号均拒绝关闭对象。先冻结状态并摘取客户端，再在锁外做阻塞关闭。

回归包括五模式初始化前/后的 Close、getClient/TCP/UDP 拒绝再次使用，以及初始化和 Close 并发。不把普通连接关闭当成整个代理适配器关闭。

## 3. Mihomo UDP 目标地址验证

单包与批量入口统一检查 nil、typed-nil UDP/ICMP 及嵌入核心自定义 nil 地址；不再先解引用 target.Port。普通 UDP 地址走类型分支，不做反射；有效域名地址继续透传。

整批先验证地址及 UDP-port-zero ICMP Echo 载荷，再允许任何前缀写入。有效普通 UDP 批次保留原 WriteBatch 快路径，混合 ICMP 批次继续使用原逐包转换。不承诺撤回已被下游接纳后才失败的数据。

回归覆盖单包拒绝、两种后端的非法批次零前缀写入、非法 ICMP、有效 IPv4/IPv6/域名、混合 ICMP 和普通 UDP 的批处理保留。typed-nil 属于已确认 API 边界问题，未证明公网未认证报文能直接构造这种 Go 值。

## 验收

修复提交：`cd529b4156f7c595005d8747c127fc16c4268f27`。

- 本机 SDK：stock/default 与 patched/http2legacy 两套 internal/pkg 全量测试、vet 通过；载体/UDP 生命周期定向测试及真实 Xray vendor 中的 30 轮 SDK 定向回归通过。
- 两个真实 Xray 实例经 JSON loader、proxySettings/freedom 链式转发：五模式 TCP/UDP、同载体多逻辑连接、先结束创建载体的逻辑连接后其余流继续通信，连续 3 轮通过。未仅用 fake dialer 代替接入验收。
- Xray Chitanda/UDP Hub 全套、配置回归和相关 vet 通过。
- Mihomo config/outbound/sing_tun/SOCKS/tunnel 回归、相关 vet，以及新增关闭/输入验证 10 轮通过；原审查的关闭后重建与 typed-nil overlay 用例各 3 轮通过。
- Xray 与带 with_gvisor,http2legacy 的 Mihomo：Linux amd64/arm64 交叉编译通过。ARM 仅交叉编译，不冒称目标机运行压测。
- Python 脚本 24 项测试、修改工作流 YAML/shell 语法、格式及 diff 空白检查通过。

合并前 [Linux CI 验收](https://github.com/chitanda-project/chitanda/actions/runs/38703912632) 四组全部成功，受验代码为上述修复提交：

| 对象 | 通过内容 |
| --- | --- |
| stock SDK / Go 1.26 | default/http2legacy 两套 internal/pkg 全量 race；载体/UDP 生命周期 30 轮 race |
| stock SDK / Go 1.27 | default/http2legacy 两套 internal/pkg 全量 race；载体/UDP 生命周期 30 轮 race |
| 注入 Xray / patched SDK | Chitanda 与配置接入 race；载体/UDP 生命周期 30 轮 race；五模式真实链式 10 轮 race；Linux 构建 |
| 干净注入 Mihomo | config/outbound/sing_tun/SOCKS/tunnel 接入 race；关闭/输入验证 30 轮 race；with_gvisor,http2legacy Linux 构建 |

审计只使用 GitHub 托管 runner，不占用生产服务器做源码/race 验收。最终提交补充 README、发布说明与本验收记录，未改动已经受验的实现和测试逻辑。

## 升级范围和未改动项

没有协议格式、密钥派生、配置项、拥塞控制或缓冲预算变更。本轮主要更新客户端 SDK/Xray 出站/Mihomo；既有服务端无需为本轮线格式同步升级，但此前服务端修复仍需要对应版本，不应混淆。

未部署、重启生产代理、修改路由器/IEPL/Realm，未调整线上 HTTP 健康检查的 URL、频率、超时或切换阈值。也未新增 WAN 饱和速率、尾延迟或丢包测试，不声称单流/多流吞吐提升或所有断线原因已消失。

main 推送触发正式打包；审计构建通过与正式多架构发布完成、实际设备已安装，是三个不同状态。
