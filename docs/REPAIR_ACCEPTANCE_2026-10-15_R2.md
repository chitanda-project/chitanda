# 2026-10-15 第二轮修复验收

## 范围与兼容性

基于 main `1cc1118d3f733cb4b70e16c189bd9dfe4c015f5e`，修复复审中新增确认的三个遗漏。它们是新发现，不等于由该提交引入。原先的缺陷证明用例重复 3 次失败，修改后相同 overlay 用例重复 3 次通过，并加入正式回归。

没有协议格式、密钥派生或配置项变更。客户端关闭修复随 SDK/Mihomo/Xray 客户端更新；末批 UDP 修复需要更新 Xray 服务端；短域名解析在共享 codec 中，接收相应报文的一端需要更新。可以分步部署，但只更新客户端不能修复旧服务端的接纳问题。

本次只上传 SDK-only 源码/测试到明确授权的隔离目录验收，没有生产密钥、PSK、配置或日志。没有部署生产代理、重启生产服务或修改路由器/IEPL/Realm。

## 修复实现

### 1. stream/H1 客户端统一关闭管理

- 在原始 TCP socket 层登记所有权，保留外层 RawStream 的原有类型、WriteBatch、认证 EOF、CloseRead/CloseWrite 和 TCP keepalive/NoDelay 行为；不在每包热路径增加全局生命周期锁。
- Plain-UDP 关联登记到同一客户端生命周期，Close 幂等，唤醒待决读取、撤销保留的拨号上下文、清理响应重放窗口并注销资源；关闭错误可用 `errors.Is(err, net.ErrClosed)` 判断。
- Client.Close 在短锁内冻结接纳并摘取连接表，在锁外取消解析/拨号/握手、关闭 socket。不持全局锁等待 I/O 或不透明的调用方回调。
- 注册和关闭快照使用同一把锁；忽略取消并晚返回的拨号结果立即关闭，不再发布给调用方。正常单独关闭连接会注销，不能一直积累在客户端表中。
- 开始操作时保留上下文 values，并用取消钩子约束 DNS/拨号/握手；TCP 握手仍应用调用方的原始 socket deadline。成功交接后移除调用方取消钩子，但保留下游核心可能使用的上下文直到 socket/Client 关闭，避免成功后 defer cancel 把 Xray 链式转发任务杀死。
- 对完全不响应取消的外部 resolver/dialer，SDK 无法强行终止其执行；Close 不等待它，且其晚返回的资源不会逃逸。调用方仍必须实现可取消、可关闭的回调。

### 2. 处理并释放 UDP 末批报文

Xray 的 native Plain-UDP 与 H3 外层接收循环均先消费本次 MultiBuffer，再处理同次返回的错误。批量 helper 统一 defer 释放剩余 Buffer；Plain-UDP 在认证解码得到 owned 明文后立即释放外层密文，避免持有它等待路由/目标 I/O。

保持认证、重放、逐用户上下文和按目标路由逻辑不变。EOF/错误后仍结束该关联，不承诺已关闭关联还能收到最后一包的返回响应；本修复不是公网零丢包保证。

### 3. Plain-UDP 按 ATYP 校验长度

认证前只检查公共固定头、ATYP 和 tag 的最低字节数，认证后分别校验 IPv4、IPv6、域名长度及端口。短域名的合法地址不再被 IPv4 的最小长度误拒绝；空域名、截断地址和未知 ATYP 仍拒绝。

不修改加密身份、时间偏差、来源/会话或防重放检查；降低错误的固定长度下限不等于允许未认证报文。

## 验收结果

| 对象 | 已执行结果 |
| --- | --- |
| SDK / Windows amd64 Go 1.27.0 | 默认与 patched legacy 两条 H2 路径的 internal/pkg 全套回归和 vet 通过 |
| SDK / Linux amd64 Go 1.27.2 | 默认与 patched legacy 两条路径的全套 race 通过；legacy 约 3分3秒，default 约 1分45秒；新增 Raw 生命周期与地址边界用例额外连续 20 轮 race 通过 |
| Raw 生命周期 | 活动 TCP/UDP 关闭、待决 DNS/拨号/握手、晚返回结果、并发幂等关闭、独立关联、上下文交接、RawStream batch 接口保留，Windows 连续 10 轮通过 |
| Plain-UDP 地址 | 1/2/255 字节域名、IPv4/IPv6、ICMP 地址、空/小 payload、双方向往返和篡改拒绝；逐字节截断、空域名负向用例通过 |
| Xray `v1.260327.0` | Chitanda/UDP Hub 全套、配置回归及相关 vet 通过；已有五模式、并发、空闲恢复、多用户计费回归包含在内 |
| UDP 末批边界 | native 及真实初始化的 h2/h3/auto，data+EOF/data+unexpected EOF/data+timeout，含多 Buffer、nil/空/无效报文与释放断言，连续 30 轮通过 |
| Xray 真实链式出站 | 两个真实 Xray 实例，dokodemo → Chitanda outbound → proxySettings/freedom → Chitanda inbound → echo；stream/H1 的 TCP、UDP 多次往返，连续 3 轮通过 |
| Mihomo `v1.19.32` | config/outbound/sing_tun/SOCKS/tunnel 的 Chitanda 回归与 vet 通过；真实 RawStream/H1 TCP echo 和 UDP 关联在 adapter.Close 后终止，连续 10 轮通过 |
| 交叉编译 | Xray Linux amd64/arm64；带 with_gvisor,http2legacy 的 Mihomo Linux amd64/arm64，通过 |
| 脚本与差异 | 现有 24 项 Python 脚本测试通过；格式、diff 空白检查通过 |

本机 Xray 首次完整运行中的两个用例因默认用户目录不可写失败；统一指定工作区隔离 `CHITANDA_STATE_DIR` 后重新全量通过，没有更改用户目录权限或清空生产重放文件。

Linux 验收使用单独临时 systemd 单元，CPUQuota=100%、Nice=10、GOMAXPROCS=1、GOMEMLIMIT=256MiB、MemoryMax=384MiB、MemorySwapMax=128MiB；不修改系统 Go。官方 Go 归档经官方 SHA256 核验后使用。两套全量 race 的峰值达到 384MiB，分别约 63/29MiB swap，不能将隔离验收描述为不消耗生产机资源。

验收后已核对并删除本轮唯一隔离目录 `/var/tmp/chitanda-repair-20261015-r2`（源码、临时 Go、缓存与测试状态均在其中）。生产 x-ui/Xray PID 仍为 1994576/1994581，启动时间仍为 2026-10-14 12:48:27（服务器本地时间），x-ui 的 NRestarts=0；未重启或替换生产代理。

下游接入在本机执行的是普通测试/vet，不冒充本轮 Linux 下游集成 race；GitHub 接入 race 门禁仍保留。ARM 为交叉编译，不是 ARM 运行或 WAN 压测。

## 未扩大的结论

未做新的公网单流/多流吞吐、尾延迟或丢包率压测；没有承诺速率提升、不可识别或所有漏洞已消失。ICMP 路由/计费一致性、Plain-UDP batching/HOL、自适应扩池指标及生产身份配置仍按 [第一轮记录](REPAIR_ACCEPTANCE_2026-10-15.md) 独立列为待办，本次未伪称完成。

推送会按既有工作流自动打包，但不等于产物已发布、通过目标设备运行验收或已部署到生产。
