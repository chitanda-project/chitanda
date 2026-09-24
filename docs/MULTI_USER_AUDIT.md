# 多用户实现审计与验收状态

基线：`main` 2dbb63f（之后的 2fcbd72 仅更新 Mihomo 发布记录）；送审：`dev` 3f8a14b。该审计覆盖 SDK、Xray 注入适配、构建与两台 Linux/ARM 节点的隔离端口性能；不代表 3X-UI 适配、正式服务部署或抗封锁效果验收。测试节点为 170.9.59.149 与 168.138.209.1，未触碰正式服务。

## 已发现并修正

- 原 Xray UDP replay registry 扩容会复制包含锁的结构体，改为构造时定长初始化；修正请求上下文中切片复制，对 `OverrideDestinationForProtocol` 字符串切片进行防御性拷贝，并移除了此前对 `ExcludeForDomain` 的切片操作（在 CI 固定的 Xray v1.260327.0 中其为 `[]string`，但在较新 Xray 上游如 main 中已重构为 `geodata.DomainMatcher` 接口；移除独立的 append 并直接沿用 `previous.SniffingRequest` 浅拷贝，兼顾了旧版切片与新版接口的跨版本兼容）。
- 全栈 Xray 实测发现：原生 UDP 包级认证用户被连接级入站上下文覆盖，TCP 正常但 UDP 不记入用户计数器。现调整路由上下文的值优先级，保持连接生命周期的同时优先使用已认证包级身份；回归检查两个用户的 TCP 与 UDP 上下行精确归账。
- 新增 Xray 策略和 Stats 计数器回归；用户计数仍依赖对应 `Level` 启用 `statsUserUplink`/`statsUserDownlink`。
- **解耦 UDP 路径以消除试解密开销（方案 A 落地）**：用户确认生产部署（如 3X-UI / Xray 标准实践）中各入站端口均有独立确定的协议与 Transport，无需在同端口混跑 Stream 与 H3 UDP。因此在 `integration/xray/inbound.go` 中完成路径分立：
  - `h2`、`h3` 与 `auto` 入站：UDP 路径专供 HTTP/3 (QUIC Datagrams)，收到 UDP 报文直接投递 `vconn`，不执行 Plain-UDP 多密钥试解密；这仅移除了该项开销，**不等于 H3 UDP 已无丢包瓶颈**；
  - `stream`、`h1` 与 `plain-h1` 入站：UDP 路径专供 Native Plain-UDP，仅在此类入站中初始化 `userCodecs` 并按包级多用户解密路由；
  - `TestH3AndPlainUDPDemuxing` 使用真实的 `auto` 与 `stream` 实例断言底层状态；从随机 nonce 中选取首字节不满足 QUIC 固定位的、未经篡改且可成功解密的 Plain-UDP 密文，再以尾随 QUIC 包的信号形成因果序（FIFO Causal Flush），验证没有试解密或串账，不依赖固定 `50ms` 盲等；
  - `virtualPacketConn` 移除了生产收包路径的原子计数，改为默认 `nil` 的测试钩子 `onFeed`；生产路径仍有一次 `nil` 判断，不宣称整个钩子零开销，实际吞吐影响应在目标机基准中检验。

## 已运行的门禁

- `go test -mod=mod ./internal/... ./pkg/... -count=1 -timeout=180s`：通过；dev 专用 Linux Actions 在 3f8a14b 上的 SDK 与注入 Xray `-race`、vendor 补丁及构建工作流均通过（[运行记录](https://github.com/chitanda-project/chitanda/actions/runs/35943421376)）。
- 注入 Xray 后 `go test -mod=mod ./proxy/chitanda -count=1 -timeout=180s`：通过（40+ 项测试全绿）；新增真实 H3/auto 双用户分别连通及同一入站并发身份测试、分 Transport UDP 路由回归测试。
- 真实 Xray JSON 入站 + Freedom 出站 + Policy/Stats 全栈回环：两个用户的 Stream TCP 与原生 UDP 上下行计数精确归属，本地重复运行 10 次通过。
- `go test -mod=mod ./infra/conf -run Chitanda -count=1 -timeout=120s`：通过。
- `go vet`（SDK、Xray 适配与配置包）及 `go build -mod=mod ./main`（注入 Xray）：通过。
- 发布流程实际采用的 Xray 最新 release 标签 `v26.3.27` 与原审计工作流固定的 `v1.260327.0` 不是同一提交；现已将 dev 审计门禁改为动态解析发布标签，避免日后只测试过时上游。另在已授权 ARM64 测试机的隔离目录，基于 `v26.3.27` 和 dev 3f8a14b 完成注入、Xray 根模块 vendor 补丁、QUIC/HTTP3 测试、Chitanda 适配与配置 `-race`、`go build -mod=vendor ./main`，全部通过；构建 SHA-256 为 `94a46508d4066c192e817492e9033dfbda8063def599f5b72dd6f58384dca8c0`。
- 全量 `./infra/conf` 有非 Chitanda 用例 `TestToCidrList` 因验证副本缺少 `geoip.dat` 失败；不能记为全量通过。
- 仓库根目录的 `go test ./...` 不适用于当前注入式集成布局：`integration/xray`、`integration/mihomo*` 依赖各自上游源码中的类型；应以 SDK 测试和注入后的上游包测试作为门禁。

## Linux/ARM 隔离端口实测（2026-09-23 至 24 日）

- 30 用户最坏位置 RawStream ClientHello 匹配：11.9–20.3 µs/op（三轮），低于计划的 25 µs/op；只证明这组 ARM 硬件和样本。
- TCP 单流：同窗口裸 TCP 约 1.46 Gbps；Xray H2 1/30 用户约 901/895 Mbps，Stream 1/30 用户约 1.34/1.36 Gbps，Auto 30 用户约 893 Mbps。Xray H2 原默认接收窗口造成约 75–82 Mbps；与独立服务端一致的 15 MiB 接收窗口修正后，单流恢复到上述范围，但该窗口增加并发缓冲的资源暴露面。
- TCP 四流：H2 1/30 用户约 1.06/0.98 Gbps，Stream 1/30 用户约 1.64/1.50 Gbps。节点共享 CPU 的 steal 波动明显，不能将小幅差值归因于密钥位置。
- Plain-UDP 100 Mbps、1200 字节包：Stream 1/30 用户约 97/93.5 Mbps；裸 UDP 200 Mbps 约 197–199 Mbps，近零丢包。H3 UDP 在 50 Mbps 时单/30 用户均约 46.5 Mbps、约 5% 总丢包，主要集中在首秒；100 Mbps 时波动和丢包严重。
- 独立构建的 `main` 单用户 H3 UDP 也复现高丢包（50 Mbps 约 46 Mbps、6.4%；100 Mbps 某轮约 32.6 Mbps、67%）。`dev` 单用户在相近测试中 100 Mbps 接收范围约 19–45 Mbps，不能从高波动样本推断 dev 相比 main 有确定的吞吐变化。H3 瓶颈是原有路径问题，不是多用户试解密回归。
- Xray 根模块原发布流程未使用 Chitanda 的 QUIC vendor 性能补丁。隔离构建修正后，两端同一产物的 H3 UDP 在 100 Mbps 两轮实收 77.4/97.1 Mbps；200 Mbps 两轮均约 68 Mbps、约 65% 丢包。数值来自保留的 iperf3 原始 JSON；**这是部分改善，不是 200 Mbps 验收通过**。详情见 `docs/UDP_AUDIT_2026-09-24.md`。

## 合入判断与保留事项

1. 多用户功能、Xray 注入及发布构建的已定义门禁通过；`dev` 3f8a14b 与当前 `main` 2fcbd72 的 Git 合并预检无冲突。此处不等于正式环境部署验收。
2. H2 接收流控窗口为每连接及每流 15 MiB，用来保持约 100 ms RTT 下的单流速率。若大量未认证连接并发填满窗口，内存暴露面会扩大；尚无正式服务长时间压力与故障恢复数据，部署时须限制入站并发、监控 RSS 与连接数。
3. H3 UDP 200 Mbps 仍有约 65% 丢包；反向高负载、尾延迟及不同节点复测未完成。若本次合入仅以“多用户不回归”为范围，必须在发布说明显著保留该已知限制；不得宣称 UDP 速率目标已完成。

结论：以“多用户及 Xray 接入无明确回归”为本次合入范围，当前 `dev` 可进入合入 `main` 的决策；H3 UDP 200 Mbps 与正式生产内存压力并未验收。未经用户明确指示，不执行合并。
