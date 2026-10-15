# 2026-10-15 边界、接入与发布修复验收

## 结论与范围

基于 main `9bf10548c9c8413e7e38ec05e8cacde2b660ccdc`，修复本轮复审中能稳定复现的四个边界错误及 H2 构建兼容问题，并实施两项低风险 TCP 优化、发布依赖与产物验证改进。

相对 2026-10-14 版本没有协议格式或密钥派生变化。客户端 SDK 修复随 Xray/Mihomo 内嵌客户端更新；Xray UDP pipe 适配和读缓冲改进随 Xray 更新。可以分步更新，但一端升级不等于包含另一端修复。从更旧版本升级仍须遵守 README 的认证 EOF、非空 server-id 双端一致等兼容要求。

没有部署生产内核、修改生产配置/凭据、重启业务服务或改动 IEPL/Realm。通过回归不等于不存在其他漏洞，也没有证明本轮修复是 HKT 不规则超时的全部原因。

## 已修复的问题

| 问题 | 修复 | 可证伪的验收 |
| --- | --- | --- |
| Go 1.27 默认 wrapper 绕开旧 H2 窗口/padding 补丁 | 支持的 `http.Transport.HTTP2` 显式设置连接/流接收窗口；官方发布选择 patched `http2legacy` | 捕获真实 TLS/H2 帧，断言 SETTINGS 窗口为 67,108,864 B；发布接入测试还断言 DATA PADDED flag |
| H1 chunk-size 行部分读取超时后丢失状态 | 有界状态机保留长度行、payload、CRLF、trailer 的部分进度，超时可恢复，协议错误终止 | 在每个字节边界插入超时后恢复，完整字节流一致；畸形 CRLF/长度拒绝且不可恢复 |
| H1 客户端认证前无响应字节预算 | 状态/单 header 行 4KiB、header/trailer 总量各 16KiB、64 行、chunk-size 行 1KiB；严格 200/chunked/CRLF，拒绝 Content-Length 或冲突 TE | 超长响应在 ServerHello 验证前有界拒绝；状态码 2000、重复 TE、非法 header、过量 trailer 等负向用例 |
| Xray UDP WriteBatch 绕过普通写的 deadline/关闭控制 | 单包和批量共用已有有界 pipeWriteQueue；最多 64 包、单包 65,535 B，保留 datagram 边界和所有权 | 过期 deadline 不入队；阻塞后超时、清除 deadline、Close/FIN、大于 2KiB 包和调用者覆写输入回归 |
| Plain-UDP 响应窗口在服务端时钟回拨时误丢 | 到达顺序稀疏窗口 + 每认证时间戳的序号 floor + 单调退休边界；不放松认证、时间、会话与来源检查 | 真实 Codec 的合法高序号回拨响应可读；重复包、淘汰后重放、退休时间重新访问、稀疏乱序及内存上限回归 |

H1 响应仍须通过 PSK ServerHello 验证，HTTP 200 不代表认证成功。重放窗口仍要求调用方先完成认证/时间/会话/来源检查并串行化访问；发送端或接收端跨出允许时间范围的时钟跳变不能保证无丢包。响应 floor 最多保留 61 个秒桶，seen/ring 各最多 2048 项，退休边界不回退。

批量写超时停止调用者等待，不承诺撤回已交给下游的包；队列持有自己的缓冲直到完成，调用者不得因超时重试已接纳内容。没有用每包 goroutine 或无限排队换取表面吞吐。

## TCP 优化与发布链路

- RawStream 将同一次 WriteBatch 已提交的多个输入 slice 合并到当前阶段 record，不等待未来写入，不修改调用者 slice header；首阶段仍立即 flush，空闲回落和认证 EOF 保留。每个发生碎片合并的 writer 最多增加 32KiB scratch。
- Xray pipe 读取改用 64KiB 池化 owned lease，仅在数据被消费或关闭丢弃后归还；不提前复用仍被读取的 buffer。
- Mihomo 的 x/net 补丁从 Go 管理的 `v0.56.0` 模块 zip 创建隔离 `.chitanda-xnet`，不读取可能被旧发布脚本改过的展开源码、不再遍历修改 GOMODCACHE。QUIC 和 H2 均在接入测试前准备，测试与打包使用同一解析后的模块。
- 补丁锚点缺失/歧义、非指定版本/替换、已存在的 snapshot、模块 zip 越界成员均拒绝；不静默漏打补丁。后续上游版本变更需要重新验收，不无限强行套补丁。
- Xray、Mihomo stable/alpha 发布统一使用 `http2legacy`；Mihomo 保留 `with_gvisor`。canonical H2 线级测试复制到两种接入模块，非仅 grep 常量或反射字段。
- 发布新增 `build-info.json`：完整 Chitanda SHA、Go 版本、每个归档 SHA256、归档内原始内核 SHA256；哈希用于追溯/完整性，不等于可信签名。
- OpenClash 的 amd64 tar 在工作流中独立解包运行 `-v` 和带 SAFE_PATHS 的 `-t`。该门禁已添加并做语法检查，本地 Windows 没有冒称执行过 Linux tar 中的内核；其他架构运行验收仍需对应目标机。

源码使用 Go 1.27 默认实现时大窗口也生效，但标准库 wrapper 不支持自定义 MaxDataPadding，代码不再设置一个会被忽略的选项。只加 `http2legacy` tag、却使用未打补丁的 stock x/net，同样不保证 padding。padding 不保证不可识别或抗封锁。

## 已执行的验收

| 环境/对象 | 结果与边界 |
| --- | --- |
| Windows amd64 / Go 1.27.0 / SDK | 默认和 patched legacy 两种路径的 `internal/... pkg/...` 全套回归通过；定向边界重复通过；默认路径 vet 通过 |
| Linux amd64 / Go 1.27.2 / SDK | 两种 H2 路径均执行全套 `go test -race -p=1 ./internal/... ./pkg/...`，全部通过 |
| Xray `v1.260327.0` 注入 | `proxy/chitanda`、UDP Hub 全套及 `infra/conf -run Chitanda` 通过；包括已有五模式 TCP/UDP、并发、空闲恢复、计费回归；相关包 vet 通过 |
| Xray 新边界压力回归 | packet batch/deadline/pipe 相关测试连续 30 轮通过；实际 H2 窗口/padding 测试连续 5 轮通过 |
| Mihomo `v1.19.32` 注入 | config/outbound/sing_tun/SOCKS/tunnel 的 Chitanda 回归通过，相关包 vet 通过；从干净 upstream 副本完整执行注入、模块 zip 补丁准备和接入回归 |
| Mihomo H2 wire | 实际 64MiB SETTINGS 和 DATA padding，连续 5 轮通过 |
| 交叉编译 | Xray Linux amd64/arm64；带 `with_gvisor,http2legacy` 的 Mihomo Linux amd64/arm64 通过。编译不等于 ARM 运行压测 |
| 脚本/工作流 | Python 24 项单元测试通过；四个改动工作流 YAML 解析及 31 段 shell 的 bash -n 检查通过；diff 空白检查通过 |

Linux 验收仅上传 SDK internal/pkg/vendor 及 SDK-only go.mod，没有上传生产密钥、PSK、配置或日志。独立 systemd 临时单元：CPUQuota=100%、Nice=10、GOMAXPROCS=1、GOMEMLIMIT=256MiB、MemoryMax=384MiB、MemorySwapMax=128MiB。官方 Go 归档核对官方发布元数据 SHA256 后使用，不替换系统 Go。两套 race 运行约 3 分 4 秒/1 分 36 秒，冷编译曾达到所设内存/swap 预算；并非无资源消耗。完成后核对生产进程 PID/启动时间未变，删除精确临时目录及工具链、源码、缓存。

本轮 Xray/Mihomo 接入在本机是常规测试和 vet，**不是本轮目标 Linux 接入 race**；接入 race 门禁保留在 GitHub 构建。SDK Linux race 不能冒充整个下游集成都已做 race。

### 本地微基准（非公网结果）

同一 Windows amd64 CPU，64KiB 总输入、io.Discard、每组 3 轮：修复后 32×2KiB 的 RawStream scatter 中位约 3674.6MB/s；先前基线约 3474.1MB/s。稳态均 0B/op、0alloc/op。连续输入新中位约 4211.4MB/s，先前约 4331.6MB/s；两组不是同窗口交错 A/B，不能排除噪声或退化，不能据此宣称全场景加速。

ReplayWindow 新微基准约 150–172ns/op、稳态 0B/op/0alloc；不是整个 UDP 加解密或网络转发吞吐。

## 未宣称完成的工作

- 本轮没有公网饱和 TCP/UDP 单流、多流、正反向、冷/热 30–60 秒对照，最新业务节点速率上限仍未知；不承诺 2Gbps 或零丢包。
- Plain-UDP WriteBatch/批量 socket 收发、慢 DNS/磁盘/目标 I/O 的队头阻塞优化、按吞吐/RTT 的自适应扩池和单流条带化仍属独立设计/受控压测任务，没有以扩大队列冒充完成。
- 没有更改激进 QUIC 拥塞参数或所有节点内存预算；低内存节点仍应谨慎。
- 生产相同 PSK/server-id 的跨节点身份域、路由器激进探测阈值未擅自更改。ICMP raw-socket 路由/计费/授权一致性仍需独立策略与测试；本轮没有将其宣称为已解决。
- PSK 模式未新增前向保密；首航 OPEN 不等于首次应用 payload 到达已实现零 RTT。没有“不可识别”保证。
- 推送会触发已有自动构建，但不代表构建已完成、产物已验收运行或生产节点已安装。
