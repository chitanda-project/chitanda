# 2026-10-14 UDP 响应与传输生命周期修复验收

基线：`c2a4e25fd5e1d5ccf6e5da4137767606fb85e5e4`。本记录不表示已发现或排除所有漏洞，也不把本次微基准当作公网吞吐。

## 本次修复

- Plain-UDP 响应去重改为本关联的有限稀疏窗口，最多保留 2048 个已认证 `(timestamp, sequence)` 身份，并保留单调淘汰边界。其他关联的共享序号跨度不再挤掉合法乱序响应；已接纳包即使被淘汰仍不可重新接纳。过期、认证、方向、源地址和 session 检查保持在窗口之前。关闭时释放窗口，迟到读取不能重建它。
- H3 manager 增加永久关闭状态、进行中建连的主动取消与按 TCP/UDP 分开的 singleflight。DNS/拨号不再持 manager 表锁；结果登记前检查取消/关闭，迟到结果关闭 socket。池选择与活动计数预占在同一 carrier 锁中完成，被缩容移除的实例不能重连。
- H2 客户端关闭撤销请求并关闭受其管理的活动 H2 stream，不再只关闭 idle transport；关闭与建连相撞时预占计数只归还一次。这里选择管理 carrier 的硬关闭语义，不是热重载 graceful drain；stream/h1 返回给调用者的独立连接仍由调用者负责关闭。
- UDP 目标配额覆盖 H3 UDP/ICMP、独立 Plain-UDP 服务和 Xray 原生路由：同进程最多 1024 个创建中/存活目标，同一凭据最多 256 个；同一凭据在不同传输/监听器共享身份预算。创建失败、取消、到期和关闭 exact-once 归还。H3 每 relay 的 UDP/ICMP/创建中目标合计不超过 64；没有声称这些限额是整个进程的 RAM 硬上限。
- H3 target 创建采用按目标 singleflight，解析与拨号移出共享表锁，关闭撤销未完成创建。独立 Plain-UDP 的清理与目标创建定序，清理跳过正在工作的关联并复核最后活动时间，避免关闭后新增孤儿目标。
- 最小服务环境未配置 HOME/XDG 时，默认持久目录可使用运行账号的真实配置目录；无法找到/创建持久目录仍 fail closed，不降级到临时目录/内存缓存。推荐部署显式设置稳定 `CHITANDA_STATE_DIR`。
- H1 每个 HTTP chunk 的 header/body/CRLF 合并一次 write，校验 short write。H2 读取 buffer 池化，通过 owned lease 在消费完、短包丢弃或关闭后才归还；不提前复用仍在排队/部分消费的 buffer。

## 升级与范围

本次不改变报文格式、PSK 派生或 ServerID 规则。UDP 误丢包修复需更新接收响应的客户端内核；服务器更新获得资源配额与目标生命周期修复。H2/H3 shutdown 修复主要在客户端。没有新增首个应用 payload 的 0-RTT，没有实现单流跨 carrier 条带聚合，没有移除拥塞控制或再加大 CUBIC 窗口。

HKT 公网 DNS 的业务用途尚未确认，生产 DNS 访问控制、定时重启与所有 IEPL/Realm 配置本次未改。不能把源码修复说成已完成这些部署调整。

## 验收证据

- SDK 普通模块模式与实际 patched QUIC vendor 模式的 `internal/...`、`pkg/...` 全套测试通过；相关 vet 通过。
- 新增重复包、淘汰后重放、跨关联乱序、时间身份、关闭后拨号、关闭取消解析、TCP/UDP 独立解析、池预占/缩容、H2 活动流关闭、buffer lease 和 H1 short write 回归。关键生命周期重复 30 轮通过；新增防重放/资源/所有权相关用例重复 10 轮通过。
- 目标 Linux AMD64 完整 SDK `-race` 通过，使用实际 patched vendor。限制单核，Go 内存软目标 256MiB、硬上限 384MiB、swap 上限 128MiB；仅临时隔离目录，未加载生产配置或重启代理。第一次验收遇到已有根 go.mod 与 SDK-only vendor 清单不匹配的环境失败；随后以六项 SDK 依赖的专用 modfile 验证，不修改正式 go.mod。
- Linux `CGO_ENABLED=0` 的最小服务环境持久目录测试重复 10 轮通过，覆盖发布的纯 Go 账号查询路径。
- Xray `v1.260327.0` / `d2758a0` 的完整 proxy/chitanda、UDP Hub 回归与相关 vet 通过；新增验证 native 路由与 SDK H3 共用身份配额。
- 实际 Xray JSON loader、入站、Dispatcher 和 TCP/UDP echo 的五模式回环验收通过：stream/h1/h2/h3/auto，每种四条并发 TCP、四个 UDP 关联（1200B，逐关联 8 次往返），TCP 空闲 6 秒后继续交换 32KiB 数据。总耗时约 30.37 秒。这是功能验收，不是饱和速率/长时间丢包测试。
- Mihomo `v1.19.32` / `88dcbf7` 的 Chitanda outbound、SOCKS、tunnel 相关回归和 vet 通过；选用本项目 QUIC snapshot。
- Xray 与 Mihomo 均完成 Linux AMD64、ARM64 构建；隔离克隆仅因 VCS stamp 环境限制使用 `-buildvcs=false`，不是跳过源码编译。
- Python 注入/脚本测试 16 项通过；diff whitespace 检查通过。下游适配器 Linux race 与更广架构由打包 Actions 的既有门禁继续执行，本地常规测试不能冒充这些 CI 结果。

新响应窗口的 Windows AMD64 CPU 微基准约 190.7–196.7ns/包，稳态 0B/0alloc。有限稀疏窗口比原先密集 bitmap 使用更多的有界状态；不宣称整条 UDP 路径零分配或公网速率提升。RawStream 明文分片合并、Plain-UDP 批量 syscall、负载型动态扩容等仍需要独立性能 A/B，不在本次安全修复中冒然改架构。
