# 2026-10-13 TCP/UDP 断线代码复查

检查基线：`157f4d4d10ac7f47663cf160c5d05f47cb62a00a`，提交时间 2026-10-13 11:54:59 +08:00。同时对照了 10 月 12 日的 `b3eab4b` 优化提交。确认今天的提交引入以下两个可复现回归。它们能够造成连接不可用，但尚无用户实际游戏连接的节点日志，不能把截图 `Failed Enter Request(802010003)` 唯一归因于其中一个。

## 1. Xray 入站关闭误释放另一个入站的共享重放缓存

位置：`integration/xray/inbound.go` 的 `InboundHandler.Close`，以及 `pkg/server/stream_server.go` 的 `StreamServer.Close`。

今天新增共享缓存后，同一进程的多个入站默认使用相同稳定状态路径，每个入站取得一个引用。入站关闭先调用 `StreamServer.Close()`，后者已关闭一次缓存；入站又调用 `h.replays.Close()`，于是同一个入站消费两个引用。两个入站并存时，关闭其中一个即可把仍在工作的另一个入站所需的缓存关闭。

新 TCP 握手需要接纳 nonce；stream/h1 原生 UDP 需要接纳新的认证时间桶。缓存被误关后它们会拒绝接纳。已有 TCP 字节流不等于必定当场被关闭，已有原生 UDP 可能在下一个时间桶才表现出失败。入站删除或重建是触发条件，并非每个普通连接关闭都会触发。

新增测试 `TestSharedReplaySurvivesPeerInboundClose` 在修复前稳定失败：

```text
closing peer inbound disabled active inbound: accepted=false err=replay cache is closed
```

修复：由 StreamServer 释放当前入站的那一个缓存引用；只有没有 StreamServer 时，入站自身释放缓存。保留 Close 幂等保护、持久化和跨重启防重放，不清空状态。测试同时验证另一个入站的新 nonce、新 UDP 关联仍能接纳，重复 UDP 序号仍被拒绝。

## 2. Mihomo 把 QUIC 连接断开误当成可恢复的读取截止时间

位置：`integration/mihomo/chitanda_deadline.go` 的 `retryTimeout`。`chitandaICMPPacketConn` 尽管名字带 ICMP，也包装普通 Chitanda UDP。

今天新增的过滤逻辑对任何 `net.Error.Timeout()` 都重试。QUIC IdleTimeoutError/HandshakeTimeoutError 也满足这个接口，但它们代表物理连接终止；重新设置读取截止时间无法恢复物理连接。只要上层的读取截止时间尚未到期或已清除，ReadFrom 会继续重试失效关联，可能忙循环，阻碍上层及时清理并在后续流量到来时建立新关联。

新增测试 `TestChitandaDeadlineDoesNotRetryTransportTimeout` 在修复前失败：

```text
terminal QUIC idle timeout swallowed; dead association keeps retrying
```

修复：仅重试明确的本地 socket 截止时间错误 `os.ErrDeadlineExceeded` 或 SDK 读取截止时间错误 `context.DeadlineExceeded`，把 QUIC 连接级超时直接返回上层。新增 ReadFrom 测试验证终止错误只读取一次就返回。此问题直接影响 UDP；忙循环可能加重资源压力，但本次未证明它导致了用户 TCP 断线。

## 验证结果和边界

- 未修复源码分别运行新增测试，得到上述两个失败；不是仅凭代码猜测。
- 核心 SDK：`pkg/connio`、`pkg/client`、`pkg/auth`、`pkg/server`、`internal/plainudp` 原有测试通过（Windows，`-mod=mod`）。
- Xray 上游 `v1.260327.0` / `d2758a0` 注入修复后：`proxy/chitanda` 全套普通测试通过；共享缓存回归重复 30 次通过；持久 UDP 重放及默认状态配置更新测试通过。
- Mihomo 上游 `v1.19.32` / `88dcbf7` 注入修复后：按项目脚本选用 `.chitanda-quic-go` 修改快照；outbound、tunnel、SOCKS 的 Chitanda/RegressionMihomo 普通测试通过；截止时间及连接终止回归重复 30 次通过。
- `gofmt`、`git diff --check` 通过。未进行本次 Linux race、真实 WAN 游戏复测或线上二进制替换。Xray 本地适配测试使用 `-mod=mod`，不作为发布 vendor 构建完整验收。
- 仓库根 `-mod=vendor` 测试仍有原有 go.mod/vendor 清单不一致问题；未改动共享模块缓存，也没有为了运行测试修改生产配置。

短时回环吞吐测试和 Actions 通过不能覆盖“关闭一个入站，另一个继续运行”与“真实 QUIC 物理连接超时”场景。今天的验收文档只验证空闲 6 秒后恢复，无法排除这些回归。

修复保存在本地独立检查目录。此次未修改线上代理、服务器 DNS 或发布资源；将修复构建并更新到实际使用节点后，仍应对照游戏出错时间检查运行日志。
